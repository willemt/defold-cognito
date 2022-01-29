#if defined(DM_PLATFORM_HTML5) || defined(DM_PLATFORM_ANDROID) || defined(DM_PLATFORM_IOS)

#ifndef COGNITO_PRIVATE_H
#define COGNITO_PRIVATE_H

#include <dmsdk/sdk.h>

enum ECOGNITOCommand
{
    COGNITO_RESULT,
};

struct DM_ALIGNED(16) CognitoCommand
{
    CognitoCommand()
    {
        memset(this, 0, sizeof(CognitoCommand));
    }

    // Used for storing eventual callback info (if needed)
    dmScript::LuaCallbackInfo* m_Callback;

    // THe actual command payload
    int32_t  	m_Command;
    int32_t  	m_ResponseCode;
    void*    	m_Data;
};

struct CognitoCommandQueue
{
    dmArray<CognitoCommand>  m_Commands;
    dmMutex::HMutex      m_Mutex;
};

char* Cognito_List_CreateBuffer(lua_State* L);
void Cognito_PushError(lua_State* L, const char* error, int reason);
void Cognito_PushConstants(lua_State* L);

typedef void (*CognitoCommandFn)(CognitoCommand* cmd, void* ctx);

void Cognito_Queue_Create(CognitoCommandQueue* queue);
void Cognito_Queue_Destroy(CognitoCommandQueue* queue);
void Cognito_Queue_Push(CognitoCommandQueue* queue, CognitoCommand* cmd);
void Cognito_Queue_Flush(CognitoCommandQueue* queue, CognitoCommandFn fn, void* ctx);

#endif

#endif // DM_PLATFORM_HTML5 || DM_PLATFORM_ANDROID || DM_PLATFORM_IOS
