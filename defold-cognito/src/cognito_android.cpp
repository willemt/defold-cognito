#if defined(DM_PLATFORM_ANDROID)

#include <dmsdk/sdk.h>
#include <dmsdk/dlib/android.h>

#include <stdlib.h>
#include <unistd.h>
#include "cognito.h"
#include "cognito_private.h"

#define LIB_NAME "cognito"

struct Cognito
{
    Cognito()
    {
        memset(this, 0, sizeof(*this));
    }

    jobject         m_Cognito;
    jobject         m_CognitoJNI;


    jmethodID       m_ConfirmPassword;
    jmethodID       m_ConfirmSignUp;
    jmethodID       m_ForgotPassword;
    jmethodID       m_GetSession;
    jmethodID       m_GlobalSignOut;
    jmethodID       m_Init;
    jmethodID       m_Login;
    jmethodID       m_ResendConfirmationCode;
    jmethodID       m_SignOut;
    jmethodID       m_SignUp;

    CognitoCommandQueue m_CommandQueue;
};

static Cognito g_Cognito;

static int Cognito_Init(lua_State* L)
{
    int top = lua_gettop(L);

    const char* pool_id = luaL_checkstring(L, 1);
    const char* client_id = luaL_checkstring(L, 2);
    const char* region = luaL_checkstring(L, 3);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring pool_ids = env->NewStringUTF(pool_id);
    jstring client_ids = env->NewStringUTF(client_id);
    jstring regions = env->NewStringUTF(region);
    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_Init, pool_ids, client_ids, regions,  g_Cognito.m_CognitoJNI);

    // env->DeleteLocalRef(pool_ids);
    // env->DeleteLocalRef(client_ids);
    // env->DeleteLocalRef(regions);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_Login(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);

    if (user_id == NULL)
        return 1;
    if (password == NULL)
        return 1;

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);
    jstring passwords = env->NewStringUTF(password);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 3);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_Login, user_ids, passwords, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ConfirmPassword(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);
    const char* code = luaL_checkstring(L, 3);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);
    jstring passwords = env->NewStringUTF(password);
    jstring codes = env->NewStringUTF(code);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 4);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_ConfirmPassword, user_ids, passwords, codes, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ConfirmSignUp(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* code = luaL_checkstring(L, 2);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);
    jstring codes = env->NewStringUTF(code);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 3);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_ConfirmSignUp, user_ids, codes, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ForgotPassword(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 2);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_ForgotPassword, user_ids, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_GetSession(lua_State* L)
{
    int top = lua_gettop(L);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 1);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_GetSession, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_SignOut(lua_State* L)
{
    int top = lua_gettop(L);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_SignOut, g_Cognito.m_CognitoJNI);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_GlobalSignOut(lua_State* L)
{
    int top = lua_gettop(L);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 1);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_GlobalSignOut, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_Signup(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);
    jstring passwords = env->NewStringUTF(password);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 3);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_SignUp, user_ids, passwords, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static int Cognito_ResendConfirmationCode(lua_State* L)
{
    int top = lua_gettop(L);

    const char* user_id = luaL_checkstring(L, 1);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    jstring user_ids = env->NewStringUTF(user_id);

    CognitoCommand* cmd = new CognitoCommand;
    cmd->m_Callback = dmScript::CreateCallback(L, 2);
    cmd->m_Command = COGNITO_RESULT;

    env->CallVoidMethod(g_Cognito.m_Cognito, g_Cognito.m_ResendConfirmationCode, user_ids, g_Cognito.m_CognitoJNI, (jlong)cmd);
    // env->DeleteLocalRef(ids);

    assert(top == lua_gettop(L));
    return 0;
}

static const luaL_reg Cognito_methods[] =
{
    {"confirmSignUp", Cognito_ConfirmSignUp},
    {"confirmPassword", Cognito_ConfirmPassword},
    {"forgotPassword", Cognito_ForgotPassword},
    {"getSession", Cognito_GetSession},
    {"globalSignOut", Cognito_GlobalSignOut},
    {"init", Cognito_Init},
    {"login", Cognito_Login},
    {"resendConfirmationCode", Cognito_ResendConfirmationCode},
    {"signOut", Cognito_SignOut},
    {"signUp", Cognito_Signup},
    {0, 0}
};

#ifdef __cplusplus
extern "C" {
#endif


JNIEXPORT void JNICALL Java_com_defold_cognito_CognitoJNI_onResult(JNIEnv* env, jobject, jint responseCode, jstring result, jlong cmdHandle)
{
    const char* pl = 0;
    if (result)
    {
        pl = env->GetStringUTFChars(result, 0);
    }

    CognitoCommand* cmd = (CognitoCommand*)cmdHandle;
    cmd->m_ResponseCode = responseCode;
    if (pl)
    {
        cmd->m_Data = strdup(pl);
        env->ReleaseStringUTFChars(result, pl);
    }
    Cognito_Queue_Push(&g_Cognito.m_CommandQueue, cmd);
}

#ifdef __cplusplus
}
#endif

static void HandleResult(const CognitoCommand* cmd)
{
    if (cmd->m_Callback == 0)
    {
        dmLogWarning("Received result but no listener was set!");
        return;
    }

    lua_State* L = dmScript::GetCallbackLuaContext(cmd->m_Callback);
    int top = lua_gettop(L);

    if (!dmScript::SetupCallback(cmd->m_Callback))
    {
        assert(top == lua_gettop(L));
        return;
    }

    // It's an error
    if (cmd->m_ResponseCode == 0) {
        lua_pushnil(L);
        dmJson::Document doc;
        dmJson::Result r = dmJson::Parse((const char*) cmd->m_Data, &doc);
        char err_str[128];
        if (dmScript::JsonToLua(L, &doc, 0, err_str, sizeof(err_str)) < 0) {
        }
        dmJson::Free(&doc);
    } else {
        dmJson::Document doc;
        dmJson::Result r = dmJson::Parse((const char*) cmd->m_Data, &doc);
        if (r == dmJson::RESULT_OK && doc.m_NodeCount > 0) {
            char err_str[128];
            if (dmScript::JsonToLua(L, &doc, 0, err_str, sizeof(err_str)) < 0) {
                dmLogError("Failed converting result JSON to Lua; %s", err_str);
                lua_pushnil(L);
            } else {
                lua_pushnil(L);
            }
        } else {
            dmLogError("Failed to parse result response (%d)", r);
            lua_pushnil(L);
        }
        dmJson::Free(&doc);
    }

    dmScript::PCall(L, 3, 0);

    dmScript::TeardownCallback(cmd->m_Callback);
    dmScript::DestroyCallback(cmd->m_Callback);

    assert(top == lua_gettop(L));
}

static dmExtension::Result InitializeCognito(dmExtension::Params* params)
{
    Cognito_Queue_Create(&g_Cognito.m_CommandQueue);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();

    const char* class_name = "com.defold.cognito.Cognito";

    jclass klass = dmAndroid::LoadClass(env, class_name);
    jclass Cognito_jni_class = dmAndroid::LoadClass(env, "com.defold.cognito.CognitoJNI");

    g_Cognito.m_ConfirmPassword = env->GetMethodID(klass, "confirmPassword", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_ConfirmSignUp = env->GetMethodID(klass, "confirmSignUp", "(Ljava/lang/String;Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_ForgotPassword = env->GetMethodID(klass, "forgotPassword", "(Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_GetSession = env->GetMethodID(klass, "getSession", "(Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_GlobalSignOut = env->GetMethodID(klass, "globalSignOut", "(Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_Init = env->GetMethodID(klass, "init", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    g_Cognito.m_Login = env->GetMethodID(klass, "login", "(Ljava/lang/String;Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_ResendConfirmationCode = env->GetMethodID(klass, "resendConfirmationCode", "(Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");
    g_Cognito.m_SignOut = env->GetMethodID(klass, "signOut", "()V");
    g_Cognito.m_SignUp = env->GetMethodID(klass, "signUp", "(Ljava/lang/String;Ljava/lang/String;Lcom/defold/cognito/IResultListener;J)V");

    jmethodID jni_constructor = env->GetMethodID(klass, "<init>", "(Landroid/app/Activity;)V");
    g_Cognito.m_Cognito = env->NewGlobalRef(env->NewObject(klass, jni_constructor, threadAttacher.GetActivity()->clazz));

    jni_constructor = env->GetMethodID(Cognito_jni_class, "<init>", "()V");
    g_Cognito.m_CognitoJNI = env->NewGlobalRef(env->NewObject(Cognito_jni_class, jni_constructor));

    lua_State*L = params->m_L;
    int top = lua_gettop(L);
    luaL_register(L, LIB_NAME, Cognito_methods);

    Cognito_PushConstants(L);

    lua_pop(L, 1);
    assert(top == lua_gettop(L));

    return dmExtension::RESULT_OK;
}

static void Cognito_OnCommand(CognitoCommand* cmd, void*)
{
    switch (cmd->m_Command)
    {
    case COGNITO_RESULT:
        HandleResult(cmd);
        break;

    default:
        assert(false);
    }

    if (cmd->m_Data) {
        free(cmd->m_Data);
    }
}

static dmExtension::Result UpdateCognito(dmExtension::Params* params)
{
    Cognito_Queue_Flush(&g_Cognito.m_CommandQueue, Cognito_OnCommand, 0);
    return dmExtension::RESULT_OK;
}

static dmExtension::Result FinalizeCognito(dmExtension::Params* params)
{
    Cognito_Queue_Destroy(&g_Cognito.m_CommandQueue);

    dmAndroid::ThreadAttacher threadAttacher;
    JNIEnv* env = threadAttacher.GetEnv();
    env->DeleteGlobalRef(g_Cognito.m_Cognito);
    env->DeleteGlobalRef(g_Cognito.m_CognitoJNI);
    g_Cognito.m_Cognito = NULL;
    return dmExtension::RESULT_OK;
}

DM_DECLARE_EXTENSION(CognitoExt, "Cognito", 0, 0, InitializeCognito, UpdateCognito, 0, FinalizeCognito)

#endif //DM_PLATFORM_ANDROID
