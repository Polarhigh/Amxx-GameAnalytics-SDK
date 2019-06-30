enum any:PlayerSessionData
{
    PS_UserId[USER_ID_LENGTH],
    PS_UserIp[IP_LENGTH],
    PS_SessionUuid[UUID_LENGTH],
    PS_SessionTimestamp,
    PS_SessionsCount, // include this sessions
    bool:PS_IsSessionStarted
};

static g_player_sessions[MAX_PLAYERS][PlayerSessionData];
static Handle:g_session_storage_connection; // connection to sqlite db

// sqlite file, used for store sessions count
static g_sessions_storage_database[] = "game_analytics_sessions";

init_player_session_data(const player_id)
{
    new session_uuid[UUID_LENGTH];
    ncrypto_generate_uuid(session_uuid);

    new auth_id[USER_ID_LENGTH];
    get_user_authid(player_id, auth_id, charsmax(auth_id));

    new ip[IP_LENGTH];
    get_user_ip(player_id, ip, charsmax(ip), .without_port = true);

    new sessions_count = get_sessions_count_from_storage(player_id) + 1;
    set_sessions_count_in_storage(player_id, sessions_count);

    copy(g_player_sessions[player_id][PS_SessionUuid], charsmax(session_uuid), session_uuid);
    copy(g_player_sessions[player_id][PS_UserId], charsmax(auth_id), auth_id);
    copy(g_player_sessions[player_id][PS_UserIp], charsmax(ip), ip);
    g_player_sessions[player_id][PS_SessionTimestamp] = get_systime();
    g_player_sessions[player_id][PS_IsSessionStarted] = true;
    g_player_sessions[player_id][PS_SessionsCount] = sessions_count;
}

clear_player_session_data(const player_id)
{
    g_player_sessions[player_id][PS_SessionTimestamp] = 0;
    g_player_sessions[player_id][PS_IsSessionStarted] = false;
}

get_player_session_id(const player_id, const len, out_id[])
{
    copy(out_id, len, g_player_sessions[player_id][PS_UserId]);
}

get_player_session_ip(const player_id, const len, out_ip[])
{
    copy(out_ip, len, g_player_sessions[player_id][PS_UserIp]);
}

get_player_session_timestamp(const player_id)
{
    return g_player_sessions[player_id][PS_SessionTimestamp];
}

get_player_session_uuid(const player_id, out_uuid[UUID_LENGTH])
{
    copy(out_uuid, charsmax(out_uuid), g_player_sessions[player_id][PS_SessionUuid]);
}

get_player_sessions_num(const player_id)
{
    return g_player_sessions[player_id][PS_SessionsCount];
}

bool:is_player_session_started(const player_id)
{
    return g_player_sessions[player_id][PS_IsSessionStarted];
}

connect_to_sessions_storage()
{
    SQL_SetAffinity("sqlite");
    new Handle:db_tuple = SQL_MakeDbTuple("", "", "", g_sessions_storage_database);

    new error_code;
    new error[128];
    g_session_storage_connection = SQL_Connect(db_tuple, error_code, error, charsmax(error));

    if (!sqlite_TableExists(g_session_storage_connection, "sessions_count"))
    {
        new Handle:query = SQL_PrepareQuery(g_session_storage_connection,
         "CREATE TABLE sessions_count (user_id varchar(64) NOT NULL, count INTEGER NOT NULL);");
        SQL_Execute(query);

        query = SQL_PrepareQuery(g_session_storage_connection,
         "CREATE UNIQUE INDEX sessions_count_user_id_idu ON sessions_count(user_id);");
        SQL_Execute(query);
    }
}

close_connection_to_sessions_storage()
{
    SQL_FreeHandle(g_session_storage_connection);
}

static get_sessions_count_from_storage(const player_id)
{
    new auth_id[USER_ID_LENGTH];
    get_user_authid(player_id, auth_id, charsmax(auth_id));

    new quoted_auth_id[USER_ID_LENGTH * 2];
    SQL_QuoteString(g_session_storage_connection, quoted_auth_id, charsmax(quoted_auth_id), auth_id);

    new Handle:query = SQL_PrepareQuery(g_session_storage_connection, "SELECT count FROM sessions_count WHERE user_id='%s';", quoted_auth_id);
    SQL_Execute(query);

    if (SQL_NumResults(query) == 0)
        return 0;
    
    return SQL_ReadResult(query, 0);
}

static set_sessions_count_in_storage(const player_id, const sessions_count)
{
    new auth_id[USER_ID_LENGTH];
    get_user_authid(player_id, auth_id, charsmax(auth_id));

    new quoted_auth_id[USER_ID_LENGTH * 2];
    SQL_QuoteString(g_session_storage_connection, quoted_auth_id, charsmax(quoted_auth_id), auth_id);

    new Handle:query = SQL_PrepareQuery(g_session_storage_connection, "REPLACE INTO sessions_count(user_id, count) VALUES ('%s', %d);", quoted_auth_id, sessions_count);
    SQL_Execute(query);
}