enum ConfigSections
{
    InvalidSection,
    ApiSection,
    CommonSection
};

enum any:SdkConfigData
{
    CF_ApiEndpoint[81],
    CF_GameKey[65],
    CF_SecretKey[81],
    CF_MinSessionLength
};

new g_config_data[SdkConfigData];

static ConfigSections:g_current_section;

sdk_config_read(const filename[])
{
    new INIParser:parser = INI_CreateParser();
    INI_SetReaders(parser, "_sdk_config_on_parse_config_value", "_sdk_config_on_prase_config_section");
    INI_ParseFile(parser, filename);
    INI_DestroyParser(parser);
}

sdk_config_get_min_session_length()
{
    return g_config_data[CF_MinSessionLength];
}

public bool:_sdk_config_on_parse_config_value(INIParser:parser, const key[], const value[])
{
    if (g_current_section == ApiSection)
    {
        if (equali(key, "Endpoint"))
            copy(g_config_data[CF_ApiEndpoint], charsmax(g_config_data[CF_ApiEndpoint]), value);
        else if (equali(key, "GameKey"))
            copy(g_config_data[CF_GameKey], charsmax(g_config_data[CF_GameKey]), value);
        else if (equali(key, "SecretKey"))
            copy(g_config_data[CF_SecretKey], charsmax(g_config_data[CF_SecretKey]), value);
    }
    else if (g_current_section == CommonSection)
    {
        if (equali(key, "MinSessionLength"))
        {
            g_config_data[CF_MinSessionLength] = str_to_num(value);
        }
    }

    return true;
}

public bool:_sdk_config_on_prase_config_section(INIParser:parser, const section[])
{
    if (equali(section, "Api"))
        g_current_section = ApiSection;
    else if (equali(section, "Common"))
        g_current_section = CommonSection;
    else
        g_current_section = InvalidSection;
    
    return true;
}