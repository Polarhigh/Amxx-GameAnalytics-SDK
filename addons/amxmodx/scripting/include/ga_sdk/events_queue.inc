
#define EVENT_SPECIFIC_STRING_LENGTH 257

enum EventCategory
{
    EC_SessionStart,
    EC_SessionEnd,
    EC_Design
};

enum EventProcessingState
{
    EP_Queued,
    EP_Skip, 
    EP_Bad
};

enum any:EventData
{
    EventProcessingState:EV_State,
    EV_Timestamp,
    EV_SessionUuid[UUID_LENGTH],
    EV_SessionNum,
    EventCategory:EV_EventCategory,
    EV_EventSpecificString[EVENT_SPECIFIC_STRING_LENGTH]
};

enum any:PlayerEventsData
{
    PE_PlayerId[USER_ID_LENGTH],
    PE_PlayerIp[IP_LENGTH],
    Array:PE_Events // EventData
};

Trie:events_queue_create()
{
    return TrieCreate();
}

events_queue_destroy(Trie:events_queue)
{
    new TrieIter:it = TrieIterCreate(events_queue);
    while (!TrieIterEnded(it))
    {
        new player_events[PlayerEventsData];
        if (TrieIterGetArray(it, player_events, sizeof(player_events)))
            ArrayDestroy(player_events[PE_Events]);

        TrieIterNext(it);
    }

    TrieIterDestroy(it);
    TrieDestroy(events_queue);
}

events_queue_start_session(const Trie:events_queue, const player_id)
{
    new event[EventData];
    init_event_data(event, player_id, EC_SessionStart);
    queue_player_event(events_queue, player_id, event);
}

events_queue_end_session(const Trie:events_queue, const player_id, const session_length)
{
    new event[EventData];
    init_event_data(event, player_id, EC_SessionEnd, fmt("^"length^":%d,", session_length));
    queue_player_event(events_queue, player_id, event);
}

events_queue_design_event_with_value(const Trie:events_queue, const player_id, const design_event[], const Float:value)
{
    new event[EventData];
    init_event_data(event, player_id, EC_Design, fmt("^"event_id^":^"%s^",^"value^":%f,", design_event, value));
    queue_player_event(events_queue, player_id, event);
}

events_queue_design_event(const Trie:events_queue, const player_id, const design_event[])
{
    new event[EventData];
    init_event_data(event, player_id, EC_Design, fmt("^"event_id^":^"%s^",", design_event));
    queue_player_event(events_queue, player_id, event);
}

// all events marked as bad will not send and will removed from queue
events_queue_mark_current_session_as_bad(const Trie:events_queue, const player_id)
{
    new user_id[USER_ID_LENGTH];
    get_player_session_id(player_id, charsmax(user_id), user_id);

    new session_uuid[UUID_LENGTH];
    get_player_session_uuid(player_id, session_uuid);

    if (TrieKeyExists(events_queue, user_id))
    {
        new player_events[PlayerEventsData];
        TrieGetArray(events_queue, user_id, player_events, sizeof(player_events));

        new event[EventData];
        new events_count = ArraySize(player_events[PE_Events]);

        for (new i = 0; i < events_count; i++)
        {
            ArrayGetArray(player_events[PE_Events], i, event, sizeof(event));

            if (equal(session_uuid, event[EV_SessionUuid]))
            {
                event[EV_State] = EP_Bad;
                ArraySetArray(player_events[PE_Events], i, event);
            }
        }
    }
}

bool:events_queue_save(const Trie:events_queue, const filename[])
{
    new file = fopen(filename, "wt");
    if (file == 0)
    {
        return false;
    }

    new auth_id[USER_ID_LENGTH];
    new player_events[PlayerEventsData];
    new events_count;

    new event[EventData];

    new TrieIter:it = TrieIterCreate(events_queue);
    while (!TrieIterEnded(it))
    {
        TrieIterGetKey(it, auth_id, charsmax(auth_id));
   
        if (TrieIterGetArray(it, player_events, sizeof(player_events)))
        {
            events_count = ArraySize(player_events[PE_Events]);
            if (events_count == 0)
            {
                TrieIterNext(it);
                continue;
            }

            fprintf(file, "%s^n", auth_id);
            fprintf(file, "%s^n", player_events[PE_PlayerIp]);
            fprintf(file, "%d^n", events_count);
            
            for (new i = 0; i < events_count; i++)
            {
                ArrayGetArray(player_events[PE_Events], i, event, sizeof(event));
                fwrite_blocks(file, event, sizeof(event), BLOCK_INT);
                fprintf(file, "^n");
            }
        }

        TrieIterNext(it);
    }
    TrieIterDestroy(it);

    fclose(file);

    return true;
}

Trie:events_queue_load(const filename[])
{
    new file = fopen(filename, "rt");
    if (file == 0)
        return Invalid_Trie;

    new dummy[3];

    new Trie:events_queue = events_queue_create();
    if (events_queue == Invalid_Trie)
        return Invalid_Trie;

    new auth_id[USER_ID_LENGTH];
    new player_events[PlayerEventsData];
    new events_count_str[16];
    new events_count;

    new event[EventData];

    while (!feof(file))
    {
        if (fgets(file, auth_id, charsmax(auth_id)) == 0)
            continue;
        trim(auth_id);
        copy(player_events[PE_PlayerId], charsmax(player_events[PE_PlayerId]), auth_id);

        fgets(file, player_events[PE_PlayerIp], charsmax(player_events[PE_PlayerIp]));
        trim(player_events[PE_PlayerIp]);
        
        fgets(file, events_count_str, charsmax(events_count_str));
        trim(events_count_str);

        events_count = str_to_num(events_count_str);

        player_events[PE_Events] = ArrayCreate(sizeof(event));
        for (new i = 0; i < events_count; i++)
        {
            fread_blocks(file, event, sizeof(event), BLOCK_INT);
            ArrayPushArray(player_events[PE_Events], event);
            fgets(file, dummy, charsmax(dummy));
        }

        TrieSetArray(events_queue, auth_id, player_events, sizeof(player_events));
    }

    fclose(file);

    return events_queue;
}

events_queue_process_batches(const Trie:events_queue, const process_event_func[], const batch_func[])
{
    new auth_id[USER_ID_LENGTH];
    new player_events[PlayerEventsData];
    new events_count;
    new event_json_string[SINGLE_EVENT_LENGTH];

    new batch_json_string[SINGLE_EVENT_LENGTH * MAX_EVENTS_IN_BATCH + 2];
    new events_batch_len;

    new process_event_func_id = get_func_id(process_event_func);
    new batch_func_id = get_func_id(batch_func);

    new TrieIter:it = TrieIterCreate(events_queue);
    while (!TrieIterEnded(it))
    {
        TrieIterGetKey(it, auth_id, charsmax(auth_id));

        if (TrieIterGetArray(it, player_events, sizeof(player_events)))
        {
            events_count = ArraySize(player_events[PE_Events]);
            if (events_count == 0)
            {
                TrieIterNext(it);
                continue;
            }
        
            new batch_num = 0;
            batch_json_string[0] = '[';
            events_batch_len = 1;

            new Array:events_remaining; // EventData

            for (new i = 0; i < events_count; i++)
            {
                new event[EventData];
                ArrayGetArray(player_events[PE_Events], i, event);

                callfunc_begin_i(process_event_func_id);
                callfunc_push_str(auth_id);
                callfunc_push_str(player_events[PE_PlayerIp]);
                callfunc_push_array(event, sizeof(event));
                callfunc_end();

                if (event[EV_State] == EP_Bad)
                {
                    continue;
                }

                if (event[EV_State] == EP_Skip)
                {
                    if (events_remaining == Invalid_Array)
                        events_remaining = ArrayCreate(EventData);

                    event[EV_State] = EP_Queued;
                    ArrayPushArray(events_remaining, event);
                    continue;
                }

                create_event_json_string(auth_id, event, charsmax(event_json_string), event_json_string);

                events_batch_len += copy(batch_json_string[events_batch_len], charsmax(batch_json_string) - events_batch_len, event_json_string);
                batch_json_string[events_batch_len++] = ',';

                if (i % MAX_EVENTS_IN_BATCH == 0 && i != 0 || i == events_count - 1)
                {
                    batch_json_string[events_batch_len - 1] = ']'; // replace last comma by closing bracket
                    batch_json_string[events_batch_len++] = '^0'; // set line ending

                    callfunc_begin_i(batch_func_id);
                    callfunc_push_str(auth_id);
                    callfunc_push_str(player_events[PE_PlayerIp]);
                    callfunc_push_str(batch_json_string);
                    callfunc_end();

                    events_batch_len = 1;
                    batch_num++;
                }
            }

            ArrayClear(player_events[PE_Events]);
            // swap events array to array with remains events
            if (events_remaining != Invalid_Array)
            {
                player_events[PE_Events] = events_remaining;
                TrieSetArray(events_queue, auth_id, player_events, sizeof(player_events));
            }
        }

        TrieIterNext(it);
    }
    
    TrieIterDestroy(it);
}

static create_event_json_string(const auth_id[], const event[EventData], const len, event_json_string_out[])
{
    // <placeholder>: string
    // category: string
    // user_id: string 
    // client_ts: int
    // session_id: string
    // session_num: string
    static g_shared_format[256] = 
    "{%s^"category^":^"%s^",^"device^":^"unknown^",^"v^":2,^"user_id^":^"%s^",^"client_ts^":%d,^"sdk_version^":^"rest api v2^",^"os_version^":^"windows 10^",^"manufacturer^":^"_^",^"platform^":^"windows^",^"session_id^":^"%s^",^"session_num^":%d}";

    formatex(event_json_string_out, len, g_shared_format,
        event[EV_EventSpecificString],
        get_category_str(event[EV_EventCategory]),
        auth_id,
        event[EV_Timestamp],
        event[EV_SessionUuid],
        event[EV_SessionNum]
    );
}

static init_event_data(event[EventData],
                       const player_id,
                       const EventCategory:event_category,
                       const event_specific_string[] = "")
{
    new session_uuid[UUID_LENGTH];
    get_player_session_uuid(player_id, session_uuid);
    copy(event[EV_SessionUuid], charsmax(session_uuid), session_uuid);
    event[EV_State] = EP_Queued;
    event[EV_Timestamp] = get_systime();
    event[EV_SessionNum] = get_player_sessions_num(player_id);
    event[EV_EventCategory] = event_category;
    copy(event[EV_EventSpecificString], charsmax(event[EV_EventSpecificString]), event_specific_string);
}

static queue_player_event(const Trie:events_queue, const player_id, const event[EventData])
{
    new user_id[USER_ID_LENGTH];
    get_player_session_id(player_id, charsmax(user_id), user_id);

    if (!TrieKeyExists(events_queue, user_id))
        add_player_in_events_queue(events_queue, player_id);

    new player_events[PlayerEventsData];
    TrieGetArray(events_queue, user_id, player_events, sizeof(player_events));

    ArrayPushArray(player_events[PE_Events], event);
}

static add_player_in_events_queue(const Trie:events_queue, const player_id)
{
    new player_events[PlayerEventsData];
    player_events[PE_Events] = ArrayCreate(EventData);
    get_player_session_id(player_id, charsmax(player_events[PE_PlayerId]), player_events[PE_PlayerId]);
    get_player_session_ip(player_id, charsmax(player_events[PE_PlayerIp]), player_events[PE_PlayerIp]);

    TrieSetArray(events_queue, player_events[PE_PlayerId], player_events, sizeof(player_events));
}

get_category_str(EventCategory:category)
{
    new category_str[16];

    if (category == EC_SessionStart)
        copy(category_str, charsmax(category_str), "user");
    else if (category == EC_SessionEnd)
        copy(category_str, charsmax(category_str), "session_end");
    else if (category == EC_Design)
        copy(category_str, charsmax(category_str), "design");

    return category_str;
}