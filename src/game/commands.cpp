namespace server
{
    void insufficientpermissions(clientinfo *ci)
    {
        srvmsgft(ci->clientnum, CON_EVENT, "\fs\f3Error:\fr Insufficient permissions.");
    }
    
    void invalidclient(clientinfo *ci)
    {
        srvmsgft(ci->clientnum, CON_EVENT, "\fs\f3Error:\fr Invalid client specified.");
    }
    
    void cmd_ip(clientinfo *ci, vector<char*> args)
    {
        if(hasadmingroup(ci) || hasmastergroup(ci))
        {
            if(args.length() < 2)
            {
                srvmsgft(ci->clientnum, CON_EVENT, "\fs\f3Error:\fr Usage: \fs\f2ip <cn>\fr");
                return;
            }
            
            int tcn = atoi(args[1]);
            clientinfo *tci = getclientinfo(tcn);
            
            if(tci)
            {
                uint ip = getclientip(tci->clientnum);
                uchar* ipc = (uchar*)&ip;
                srvmsgft(ci->clientnum, CON_EVENT, "\fs\f2Info:\fr Client(%i) ip: %hhu.%hhu.%hhu.%hhu", tci->clientnum, ipc[0], ipc[1], ipc[2], ipc[3]);
            }
            else
            {
                invalidclient(ci);
            }
        }
        else
        {
            insufficientpermissions(ci);
        }
    }
    
    void cmd_master(clientinfo *ci, vector<char*> args)
    {
        if(hasadmingroup(ci) || hasmastergroup(ci))
        {
            auth::setprivilege(ci, true, PRIV_MODERATOR, true, true);
        }
        else
        {
            insufficientpermissions(ci);
        }
    }
    
    void cmd_admin(clientinfo *ci, vector<char*> args)
    {
        if(hasadmingroup(ci))
        {
            auth::setprivilege(ci, true, PRIV_ADMINISTRATOR, true, true);
        }
        else
        {
            insufficientpermissions(ci);
        }
    }
    
    void cmd_names(clientinfo *ci, vector<char*> args)
    {
        if(hasadmingroup(ci) || hasmastergroup(ci))
        {
            if(args.length() < 2)
            {
                srvmsgft(ci->clientnum, CON_EVENT, "\fs\f3Error:\fr Usage: \fs\f2names <cn>\fr");
                return;
            }
            
            int tcn = atoi(args[1]);
            clientinfo *tci = getclientinfo(tcn);
            
            if(tci)
            {
                uint ip = getclientip(tci->clientnum);
                uint mask = 0xFFFF;
                
                auth::namesrequest(ci, ip, mask);
            }
            else
            {
                invalidclient(ci);
            }
        }
        else
        {
            insufficientpermissions(ci);
        }
    }
    
    struct command
    {
        const char *name;
        int minprivilege;
        void (*functionPtr)(clientinfo *ci, vector<char*> args);
    };
    
    void cmd_listcommands(clientinfo *ci, vector<char*> args);
    
    command commands[] = {
        {"ip", PRIV_NONE, &cmd_ip},
        {"master", PRIV_NONE, &cmd_master},
        {"admin", PRIV_NONE, &cmd_admin},
        {"names", PRIV_NONE, &cmd_names},
        {"listcommands", PRIV_NONE, &cmd_listcommands}
    };
    
    void cmd_listcommands(clientinfo *ci, vector<char*> args)
    {
        vector<char> commandlist;
        
        bool first = true;
        for(unsigned int i = 0; i < sizeof(commands)/sizeof(command); i++)
        {
            if(commands[i].minprivilege <= ci->privilege)
            {
                if(first) first = false;
                else commandlist.put(", ", 2);
                commandlist.put(commands[i].name, strlen(commands[i].name));
            }
        }
        srvmsgft(ci->clientnum, CON_EVENT, "\fs\f4Available commands:\fr %s", commandlist.getbuf());
    }
    
    void trycommand(clientinfo *ci, const char *cmd) 
    {
        logoutf("Command: %s: %s", ci->name, cmd);
    
        vector<char*> args;
        explodelist(cmd, args);
        
        if(args.length() < 1) return;
        
        for(unsigned int i = 0; i < sizeof(commands)/sizeof(command); i++)
        {
            if(!strcmp(commands[i].name, args[0]))
            {
                if(commands[i].minprivilege <= ci->privilege)
                {
                    (*commands[i].functionPtr)(ci, args);
                }
                else insufficientpermissions(ci);
                return;
            }
        }
        srvmsgft(ci->clientnum, CON_EVENT, "\fs\f3Error:\fr Unknown command.");
    }
}

