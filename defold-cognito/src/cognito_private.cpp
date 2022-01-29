#if defined(DM_PLATFORM_HTML5) || defined(DM_PLATFORM_ANDROID) || defined(DM_PLATFORM_IOS)

#include <dmsdk/sdk.h>

#include "cognito.h"
#include "cognito_private.h"
#include <string.h>
#include <stdlib.h>

// Creates a comma separated string, given a table where all values are strings (or numbers)
// Returns a malloc'ed string, which the caller must free
char* Cognito_List_CreateBuffer(lua_State* L)
{
    int top = lua_gettop(L);

    luaL_checktype(L, 1, LUA_TTABLE);
    lua_pushnil(L);
    int length = 0;
    while (lua_next(L, 1) != 0) {
        if (length > 0) {
            ++length;
        }
        const char* p = lua_tostring(L, -1);
        if(!p)
        {
            luaL_error(L, "Cognito: Failed to get value (string) from table");
        }
        length += strlen(p);
        lua_pop(L, 1);
    }

    char* buf = (char*)malloc(length+1);
    if( buf == 0 )
    {
        dmLogError("Could not allocate buffer of size %d", length+1);
        assert(top == lua_gettop(L));
        return 0;
    }
    buf[0] = '\0';

    int i = 0;
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        if (i > 0) {
            dmStrlCat(buf, ",", length+1);
        }
        const char* p = lua_tostring(L, -1);
        if(!p)
        {
            luaL_error(L, "Cognito: Failed to get value (string) from table");
        }
        dmStrlCat(buf, p, length+1);
        lua_pop(L, 1);
        ++i;
    }

    assert(top == lua_gettop(L));
    return buf;
}

void Cognito_PushError(lua_State* L, const char* error, int reason)
{
    if (error != 0) {
        lua_newtable(L);
        lua_pushstring(L, "error");
        lua_pushstring(L, error);
        lua_rawset(L, -3);
        lua_pushstring(L, "reason");
        lua_pushnumber(L, reason);
        lua_rawset(L, -3);
    } else {
        lua_pushnil(L);
    }
}

void Cognito_PushConstants(lua_State* L)
{

}

void Cognito_Queue_Create(CognitoCommandQueue* queue)
{
    queue->m_Mutex = dmMutex::New();
}

void Cognito_Queue_Destroy(CognitoCommandQueue* queue)
{
    dmMutex::Delete(queue->m_Mutex);
}

void Cognito_Queue_Push(CognitoCommandQueue* queue, CognitoCommand* cmd)
{
    DM_MUTEX_SCOPED_LOCK(queue->m_Mutex);

    if(queue->m_Commands.Full())
    {
        queue->m_Commands.OffsetCapacity(2);
    }
    queue->m_Commands.Push(*cmd);
}

void Cognito_Queue_Flush(CognitoCommandQueue* queue, CognitoCommandFn fn, void* ctx)
{
    assert(fn != 0);

    if (queue->m_Commands.Empty())
    {
        return;
    }

    dmArray<CognitoCommand> tmp;
    {
        DM_MUTEX_SCOPED_LOCK(queue->m_Mutex);
        tmp.Swap(queue->m_Commands);
    }

    for(uint32_t i = 0; i != tmp.Size(); ++i)
    {
        fn(&tmp[i], ctx);
    }
}

#endif // DM_PLATFORM_HTML5 || DM_PLATFORM_ANDROID || DM_PLATFORM_IOS
