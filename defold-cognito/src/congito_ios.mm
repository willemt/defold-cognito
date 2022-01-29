#if defined(DM_PLATFORM_IOS)

#include <dmsdk/sdk.h>

#include "cognito.h"
#include "cognito.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>

#import "AWSCore/AWSCore.h"
#import "AWSCore/AWSCategory.h"
#import "AWSCognitoIdentityProvider/AWSCognitoIdentityUserPool.h"
#import "AWSCognitoIdentityProvider/AWSCognitoIdentityUser.h"

#define LIB_NAME "cognito"

struct Cognito;

struct Cognito
{
    Cognito()
    {
        memset(this, 0, sizeof(*this));
    }
    int                             m_Version;
    
    AWSCognitoIdentityUserPool *pool;
};

Cognito g_Cognito;

static void _make_error(dmScript::LuaCallbackInfo* callback, NSError* error)
{
    lua_State* L = dmScript::GetCallbackLuaContext(callback);
    int top = lua_gettop(L);

    if (!dmScript::SetupCallback(callback))
    {
        assert(top == lua_gettop(L));
        //delete response;
        return;
    }
    
    lua_pushnil(L);
    lua_newtable(L);
    lua_pushstring(L, [error.userInfo[@"__type"] UTF8String]);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, [error.userInfo[@"message"] UTF8String]);
    lua_setfield(L, -2, "message");
    dmScript::PCall(L, 3, 0);
    dmScript::TeardownCallback(callback);
    dmScript::DestroyCallback(callback);
}
static int Cognito_Init(lua_State* L)
{
    dmLogError("Cognito_Init.");

    const char* pool_id = luaL_checkstring(L, 1);
    const char* client_id = luaL_checkstring(L, 2);
    const char* region = luaL_checkstring(L, 3);
    
    AWSServiceConfiguration *serviceConfiguration = [
        [AWSServiceConfiguration alloc]
        initWithRegion:[[NSString stringWithUTF8String: region] aws_regionTypeValue]
        credentialsProvider:nil];

    AWSServiceManager.defaultServiceManager.defaultServiceConfiguration = serviceConfiguration;

    NSString* client_ids = [NSString stringWithUTF8String: client_id];
    NSString* pool_ids = [NSString stringWithUTF8String: pool_id];
    
    AWSCognitoIdentityUserPoolConfiguration *configuration = [[AWSCognitoIdentityUserPoolConfiguration alloc] initWithClientId:client_ids
    clientSecret:NULL
    poolId:pool_ids];
    
    [AWSCognitoIdentityUserPool registerCognitoIdentityUserPoolWithConfiguration:serviceConfiguration userPoolConfiguration:configuration forKey:@"UserPool"];

    g_Cognito.pool = [AWSCognitoIdentityUserPool CognitoIdentityUserPoolForKey:@"UserPool"];
    
    return dmExtension::RESULT_OK;
}

static dmExtension::Result FinalizeCognito(dmExtension::Params* params)
{
    return dmExtension::RESULT_OK;
}

static void _store_tokens_in_luatable(lua_State* L, AWSCognitoIdentityUserSession* session)
{
    lua_pushstring(L, [session.accessToken.tokenString UTF8String]);
    lua_setfield(L, -2, "accessToken");
    lua_pushstring(L, [session.refreshToken.tokenString UTF8String]);
    lua_setfield(L, -2, "refreshToken");
    lua_pushstring(L, [session.idToken.tokenString UTF8String]);
    lua_setfield(L, -2, "idToken");
}

static int _get_user_details(AWSCognitoIdentityUser* user, AWSCognitoIdentityUserSession* session, dmScript::LuaCallbackInfo* callback)
{
    [[user getDetails] continueWithSuccessBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserGetDetailsResponse *> * _Nonnull task) {
        AWSCognitoIdentityUserGetDetailsResponse *response = task.result;

        lua_State* L = dmScript::GetCallbackLuaContext(callback);
        int top = lua_gettop(L);

        if (!dmScript::SetupCallback(callback))
        {
            assert(top == lua_gettop(L));
            //delete response;
            return task;
        }

        lua_newtable(L);
        _store_tokens_in_luatable(L, session);
        lua_pushstring(L, [user.username UTF8String]);
        lua_setfield(L, -2, "username");
        lua_pushboolean(L, 1);
        lua_setfield(L, -2, "userConfirmed");

        lua_pushliteral(L, "attributes");
        lua_newtable(L);
        for (AWSCognitoIdentityUserAttributeType *attribute in response.userAttributes) {
            //print the user attributes
            NSLog(@"Attribute: %@ Value: %@", attribute.name, attribute.value);
            lua_pushstring(L, [attribute.value UTF8String]);
            lua_setfield(L, -2, [attribute.name UTF8String]);
        }
        lua_settable( L, -3 );

        lua_pushnil(L);
        dmScript::PCall(L, 3, 0);

        dmScript::TeardownCallback(callback);
        dmScript::DestroyCallback(callback);

        return nil;
    }];

    return nil;
}

static int Cognito_Login(lua_State* L)
{
    dmLogError("Cognito_Login.");
    
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);

    if (user_id == NULL || strlen(user_id) == 0)
    return 0;
    
    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 3);

    NSString* user_ids = [NSString stringWithUTF8String: user_id];
    NSString* passwords = [NSString stringWithUTF8String: password];

    AWSCognitoIdentityUser * user = [g_Cognito.pool getUser:user_ids];
    
    [[user getSession:user_ids password:passwords validationData:NULL] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserSession *> * _Nonnull task) {
        if(task.error || task.isCancelled){
            NSLog(@"FAILED login task %@", task.error);
            _make_error(callback, task.error);
            return task;
        }

        _get_user_details(user, task.result, callback);

        return task;
    }];

//     assert(top == lua_gettop(L));

    return 1;
}

static int Cognito_GetSession(lua_State* L)
{
    dmLogError("Cognito_getSession.");

    int top = lua_gettop(L);

    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 1);

    AWSCognitoIdentityUser * user = [g_Cognito.pool currentUser];

    if (!user) {
        // TODO: send error back?
        dmLogError("ERROR: No current user.");
        return 0;
    }

    [[user getSession] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserSession *> * _Nonnull task) {
        if(task.error || task.isCancelled){

            // FIXME: most probably "Authentication delegate not set", but
            // we'll assume we need to try to login
            NSLog(@"FAILED getsession task %@", task.error);

            lua_State* L = dmScript::GetCallbackLuaContext(callback);
            int top = lua_gettop(L);

            if (!dmScript::SetupCallback(callback))
            {
                assert(top == lua_gettop(L));
                return task;
            }

            lua_newtable(L);
            lua_pushboolean(L, 1);
            lua_setfield(L, -2, "getAuthenticationDetails");

            lua_pushnil(L);
            dmScript::PCall(L, 3, 0);

            dmScript::TeardownCallback(callback);
            dmScript::DestroyCallback(callback);
            return task;
        }
        _get_user_details(user, task.result, callback);
        return task;
    }];

    //     assert(top == lua_gettop(L));

    return 0;
}

static int Cognito_SignOut(lua_State* L)
{
    int top = lua_gettop(L);

    AWSCognitoIdentityUser * user = [g_Cognito.pool currentUser];

    [user signOut];

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_Signup(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);

    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 3);

    NSMutableArray * attributes = [NSMutableArray new];

    AWSCognitoIdentityUserAttributeType * email = [AWSCognitoIdentityUserAttributeType new];
    email.name = @"email";
    email.value = [NSString stringWithUTF8String: user_id];

    [attributes addObject:email];

    NSString* user_ids = [NSString stringWithUTF8String: user_id];
    NSString* passwords = [NSString stringWithUTF8String: password];

        [[g_Cognito.pool signUp:user_ids password:passwords userAttributes:@[email] validationData:nil] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserPoolSignUpResponse *> * _Nonnull task) {
            if(task.error || task.isCancelled){
            // FIXME: most probably "Authentication delegate not set", but
            // we'll assume we need to try to login
            NSLog(@"FAILED signup task %@", task.error);
            _make_error(callback, task.error);
            return task;
        }

        NSLog(@"Successfully registered user");

        // NOTE: easier if we just inject a synthetic UserNotConfirmedException
        // TODO: worth allowing user to disable this behaviour
        lua_State* L = dmScript::GetCallbackLuaContext(callback);
        int top = lua_gettop(L);

        if (!dmScript::SetupCallback(callback))
        {
            assert(top == lua_gettop(L));
            //delete response;
            return nil;
        }
        
        lua_pushnil(L);
        lua_newtable(L);
        lua_pushstring(L, "UserNotConfirmedException");
        lua_setfield(L, -2, "code");
        lua_pushstring(L, "User not confirmed");
        lua_setfield(L, -2, "message");
        dmScript::PCall(L, 3, 0);
        dmScript::TeardownCallback(callback);
        dmScript::DestroyCallback(callback);

        return nil;
    }];

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ConfirmSignUp(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* code = luaL_checkstring(L, 2);
    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 3);

    NSString* user_ids = [NSString stringWithUTF8String: user_id];
    NSString* codes = [NSString stringWithUTF8String: code];

    AWSCognitoIdentityUser * user = [g_Cognito.pool getUser:user_ids];

    [[user confirmSignUp:codes forceAliasCreation:NO] continueWithBlock: ^id _Nullable(AWSTask<AWSCognitoIdentityUserConfirmSignUpResponse *> * _Nonnull task) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (task.error){
                NSLog(@"FAILED signup task %@", task.error);
                dmLogError("FAILED signup task.");
                _make_error(callback, task.error);
            } else {

                [[user getSession] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserSession *> * _Nonnull task2) {
                    if(task2.error || task2.isCancelled){
                        NSLog(@"FAILED signup.getsession task %@", task2.error);
                        return task;
                    }
                    _get_user_details(user, task2.result, callback);
                    return task;
                }];

            }
        });
        return nil;
    }];

    assert(top == lua_gettop(L));
    return 0;
}


static int Cognito_ResendConfirmationCode(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 2);
    
    NSString* user_ids = [NSString stringWithUTF8String: user_id];

    AWSCognitoIdentityUser * user = [g_Cognito.pool getUser:user_ids];

    [[user resendConfirmationCode] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserResendConfirmationCodeResponse *> * _Nonnull task) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (task.error){
                NSLog(@"FAILED resendConfirmationCode task %@", task.error);
                dmLogError("FAILED resendConfirmationCode task.");
                _make_error(callback, task.error);
            } else {

            }
        });
        return nil;
    }];

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ForgotPassword(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 2);

    NSString* user_ids = [NSString stringWithUTF8String: user_id];

    AWSCognitoIdentityUser * user = [g_Cognito.pool getUser:user_ids];

    [[user forgotPassword] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserForgotPasswordResponse *> * _Nonnull task) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (task.error){
                NSLog(@"FAILED forgotPassword task %@", task.error);
                dmLogError("FAILED forgotPassword task.");
                _make_error(callback, task.error);
                return;
            }
            lua_State* L = dmScript::GetCallbackLuaContext(callback);
            int top = lua_gettop(L);
            if (!dmScript::SetupCallback(callback))
            {
                assert(top == lua_gettop(L));
                return;
            }
            lua_newtable(L);
            lua_pushboolean(L, 1);
            lua_setfield(L, -2, "getResetCode");
            lua_pushnil(L);
            dmScript::PCall(L, 3, 0);
            dmScript::TeardownCallback(callback);
            dmScript::DestroyCallback(callback);
        });
        return nil;
    }];
    

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ConfirmPassword(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);
    const char* code = luaL_checkstring(L, 3);
    dmScript::LuaCallbackInfo* callback = dmScript::CreateCallback(L, 4);

    NSString* user_ids = [NSString stringWithUTF8String: user_id];
    NSString* passwords = [NSString stringWithUTF8String: password];
    NSString* codes = [NSString stringWithUTF8String: code];

    AWSCognitoIdentityUser * user = [g_Cognito.pool getUser:user_ids];

    [[user confirmForgotPassword:codes password:passwords ] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserConfirmForgotPasswordResponse *> * _Nonnull task) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (task.error){
                NSLog(@"FAILED confirmForgotPassword task %@", task.error);
                dmLogError("FAILED confirmForgotPassword task.");
                _make_error(callback, task.error);
                return;
            }
            [[user getSession:user_ids password:passwords validationData:NULL] continueWithBlock:^id _Nullable(AWSTask<AWSCognitoIdentityUserSession *> * _Nonnull task2) {
                if(task2.error || task2.isCancelled){
                    NSLog(@"FAILED confirmForgotPassword.getsession task %@", task2.error);
                    dmLogError("FAILED confirmForgotPassword.getsession task.");
                    return nil;
                }
                _get_user_details(user, task2.result, callback);
                return nil;
            }];
        });
        return nil;
    }];

    assert(top == lua_gettop(L));
    return 0;
}

static const luaL_reg Cognito_methods[] =
{
    {"confirmSignUp", Cognito_ConfirmSignUp},
    {"confirmPassword", Cognito_ConfirmPassword},
    {"forgotPassword", Cognito_ForgotPassword},
    {"getSession", Cognito_GetSession},
    // {"globalSignOut", Cognito_GlobalSignOut},
    {"init", Cognito_Init},
    {"login", Cognito_Login},
    {"resendConfirmationCode", Cognito_ResendConfirmationCode},
    {"signOut", Cognito_SignOut},
    {"signUp", Cognito_Signup},
    {0, 0}
};


static dmExtension::Result InitializeCognito(dmExtension::Params* params)
{
    dmLogError("InitializeCognito.");

    lua_State*L = params->m_L;
    int top = lua_gettop(L);
    luaL_register(L, LIB_NAME, Cognito_methods);

    lua_pop(L, 1);
    assert(top == lua_gettop(L));

    return dmExtension::RESULT_OK;
}

DM_DECLARE_EXTENSION(CognitoExt, "Cognito", 0, 0, InitializeCognito, 0, 0, FinalizeCognito)

#endif // DM_PLATFORM_IOS
