#include <amxmodx>
#include <amxmisc>
#include <ncrypto>
#include <curl>
#include <sqlx>
#include <json>
#include <textparse_ini>

#define CURL_HELPER_RESPONSE_MAX_LENGTH 4096
#include <curl_helper>

#pragma semicolon 1
#pragma dynamic 32768

#pragma reqlib sqlite
#if !defined AMXMODX_NOAUTOLOAD
    #pragma loadlib sqlite
#endif

//#define GA_DEBUG

// 0 terminator included
#define IP_LENGTH 17
// 0 terminator included
#define UUID_LENGTH 37
// 0 terminator included
#define USER_ID_LENGTH 65

#define SINGLE_EVENT_LENGTH 410
// (SINGLE_EVENT_LENGTH * MAX_EVENTS_IN_BATCH + 2) must not be more then MAX_STRING_LENGTH (16384) 
#define MAX_EVENTS_IN_BATCH 25

#include <ga_sdk/events_queue>
#include <ga_sdk/player_session>
#include <ga_sdk/config_reader>

new bool:g_sdk_inited;
new Trie:g_players_events; // PlayerEventsData

// text file, used for store unsended events between maps change
new const g_events_tmp_file[] = "analytics_events.tmp";

write_ga_log(format[], any:...)
{
    new time[16];
    get_time("%m-%d-%Y", time, charsmax(time));

    new base_dir[128];
    get_basedir(base_dir, charsmax(base_dir));

    new dir[200];
    formatex(dir, charsmax(dir), "%s/logs/ga_sdk", base_dir);

    new path[256];
    formatex(path, charsmax(path), "%s/logs/ga_sdk/%s.log", base_dir, time);

    new buffer[5000];
    vformat(buffer, charsmax(buffer), format, 2);

    if (!dir_exists(dir))
        mkdir(dir);

    log_to_file(path, "%s", buffer);
}

start_session(const player_id)
{
    init_player_session_data(player_id);
    events_queue_start_session(g_players_events, player_id);
}

end_session(const player_id)
{
    if (is_player_session_started(player_id))
    {
        new session_length = get_systime() - get_player_session_timestamp(player_id);

        if (session_length < sdk_config_get_min_session_length())
            events_queue_mark_current_session_as_bad(g_players_events, player_id);
        else
            events_queue_end_session(g_players_events, player_id, session_length);
        
        clear_player_session_data(player_id);
    }
}

init_sdk()
{
    write_ga_log("[GameAnalytics] Initializing SDK...");
    g_sdk_inited = false;
    ga_send_request("init", "{^"platform^": ^"Linux^", ^"sdk_version^": ^"rest api v2^", ^"os_version^": ^"Ubuntu 16.04^"}", "init_sdk_answer");
}

public init_sdk_answer(CURL:curl, CURLcode:code, data[])
{
    curl_easy_cleanup(curl);
    curl_slist_free_all(curl_slist:data[0]);

    if (code == CURLE_OK)
    {
        new response_data[CURL_HELPER_RESPONSE_MAX_LENGTH];
        curl_helper_get_response(curl, response_data, charsmax(response_data));

        if (!curl_helper_is_response_trunc(curl))
        {
            new JSON:answer = json_parse(response_data);
            //g_timestamp_offset = get_systime() - json_object_get_number(answer, "server_ts");
            g_sdk_inited = json_object_get_bool(answer, "enabled");

            if (g_sdk_inited)
                write_ga_log("[GameAnalytics] SDK Initialized.");
            else
                write_ga_log("[GameAnalytics] Server says analytics not enabled.");
        }
        else
            write_ga_log("[GameAnalytics] Can't initialize, answer is too large to parse.");
    }
    else
    {
        new err[CURL_ERROR_SIZE];
        curl_easy_strerror(code, err, charsmax(err));
        write_ga_log("[GameAnalytics] Init failed with error #%i: %s", code, err);
    }
}

save_players_queue_to_tmp_file()
{
    new data_dir[256];
    get_datadir(data_dir, charsmax(data_dir));

    new filename[300];
    formatex(filename, charsmax(filename), "%s/%s", data_dir, g_events_tmp_file);

    events_queue_save(g_players_events, filename);
}

init_players_queue()
{
    new data_dir[256];
    get_datadir(data_dir, charsmax(data_dir));

    new filename[300];
    formatex(filename, charsmax(filename), "%s/%s", data_dir, g_events_tmp_file);

    if (g_players_events != Invalid_Trie)
        events_queue_destroy(g_players_events);

    g_players_events = events_queue_load(filename);
    if (g_players_events == Invalid_Trie)
        g_players_events = events_queue_create();
}

delete_players_queue_tmp_file()
{
    new data_dir[256];
    get_datadir(data_dir, charsmax(data_dir));

    new filename[300];
    formatex(filename, charsmax(filename), "%s/%s", data_dir, g_events_tmp_file);

    delete_file(filename);
}

ga_send_request(const api[], const data[], const complete_function[], const xforward[] = {})
{
    new CURL:curl = curl_easy_init();
    if (curl)
    {
        new hash_base64[64];
        ncrypto_hmacsha256_base64(data, g_config_data[CF_SecretKey], hash_base64, charsmax(hash_base64));

        new authorization_header[78];
        formatex(authorization_header, charsmax(authorization_header), "Authorization:%s", hash_base64);

        new curl_slist:headers;
        headers = curl_slist_append(headers, "Content-Type:application/json");
        headers = curl_slist_append(headers, authorization_header);

        if (strlen(xforward) > 0)
        {
            new xforward_header[64];
            formatex(xforward_header, charsmax(xforward_header), "X-Forwarded-For:%s", xforward);
            headers = curl_slist_append(headers, xforward_header);
        }
        
        new url[256];
        formatex(url, charsmax(url), "%s/v2/%s/%s", g_config_data[CF_ApiEndpoint], g_config_data[CF_GameKey], api);

        new request_internal_data[1];
        request_internal_data[0] = headers;

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "cstrike/addons/amxmodx/data/cert/cacert-2018-06-20.pem");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);

        curl_helper_set_write_options(curl);
        curl_easy_perform(curl, complete_function, request_internal_data, sizeof(request_internal_data));
    }
}

new g_processing_user_id[USER_ID_LENGTH];
new bool:g_skip_events;

public process_players_queue()
{
    if (!g_sdk_inited)
        return;

#if defined GA_DEBUG
    write_ga_log("[GameAnalytics] Processing started.");
#endif
    
    g_skip_events = false;
    events_queue_process_batches(g_players_events, "on_process_event", "on_batch_created");
}

public on_process_event(const auth_id[], const ip[], event[EventData])
{
    if (event[EV_State] != EP_Queued)
        return;
    
    // processing user changed, reset skip flag
    if (!equal(g_processing_user_id, auth_id))
    {
        copy(g_processing_user_id, charsmax(g_processing_user_id), auth_id);
        g_skip_events = false;
    }

    // prevent send recent sessions
    // all events after EC_SessionStart contains same session id, so skip all events until new EC_SessionStart comes
    if (event[EV_EventCategory] == EC_SessionStart) 
        g_skip_events = (get_systime() - event[EV_Timestamp]) <= sdk_config_get_min_session_length();
    
    if (g_skip_events)
        event[EV_State] = EP_Skip;
}

public on_batch_created(const auth_id[], const ip[], const batch_json_string[])
{
    ga_send_request("events", batch_json_string, "process_players_queue_answer", ip);
}

public process_players_queue_answer(CURL:curl, CURLcode:code, data[])
{
    new http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);

    curl_easy_cleanup(curl);
    curl_slist_free_all(curl_slist:data[0]);

    if (code == CURLE_OK)
    {
        if (http_code != 200)
        {
            new response_data[CURL_HELPER_RESPONSE_MAX_LENGTH];
            new length = curl_helper_get_response(curl, response_data, charsmax(response_data));

            write_ga_log("[GameAnalytics] Error sending batch. HTTP Code: %d. Length: %d. Data: %s", http_code, length, response_data);
        }
    }
    else
    {
        new err[CURL_ERROR_SIZE];
        curl_easy_strerror(code, err, charsmax(err));
        write_ga_log("[GameAnalytics] Sending batch failed with error #%i: %s; http: %d", code, err, http_code);
    }
}

public game_analytics_custom_event_handler(const plugin_id, const argc)
{
    new player_id = get_param(1);
    
    if (!is_player_session_started(player_id))
    {
        new plugin_name[64];
        get_plugin(plugin_id, plugin_name, charsmax(plugin_name));

        write_ga_log("[GameAnalytics] Can't queue event due player session not started. Plugin: %s", plugin_name);
        return;
    }

    new event[128];
    get_string(2, event, charsmax(event));
    
    if (argc > 2)
        events_queue_design_event_with_value(g_players_events, player_id, event, Float:get_param_byref(3));
    else
        events_queue_design_event(g_players_events, player_id, event);
}

public plugin_natives()
{
    register_native("game_analytics_custom_event", "game_analytics_custom_event_handler");
}

public plugin_init()
{
    register_plugin("GameAnalytics SDK", "0.1b", "Polarhigh");
    
    new cfg_dir[256];
    get_configsdir(cfg_dir, charsmax(cfg_dir));

    new filename[300];
    formatex(filename, charsmax(filename), "%s/%s", cfg_dir, "ga_sdk_config.ini");
    
    sdk_config_read(filename);

    init_players_queue();
    delete_players_queue_tmp_file();

    connect_to_sessions_storage();
    init_sdk();
    set_task(40.0, "process_players_queue", 1, .flags = "b");
}

public plugin_end()
{
    save_players_queue_to_tmp_file();
    events_queue_destroy(g_players_events);
    close_connection_to_sessions_storage();

    curl_helper_free();
}

public client_authorized(id, const authid[])
{
    if (is_user_bot(id) || is_user_hltv(id))
        return;
    
    start_session(id);
}

public client_disconnected(id, bool:drop, message[], max_len)
{
    if (is_user_bot(id) || is_user_hltv(id))
        return;

    end_session(id);
}