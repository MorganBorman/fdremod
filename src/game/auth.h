void hashpassword(int cn, int sessionid, const char *pwd, char *result, int maxlen)
{
    char buf[2*sizeof(string)];
    formatstring(buf)("%d %d ", cn, sessionid);
    copystring(&buf[strlen(buf)], pwd);
    if(!hashstring(buf, result, maxlen)) *result = '\0';
}

bool checkpassword(clientinfo *ci, const char *wanted, const char *given)
{
    string hash;
    hashpassword(ci->clientnum, ci->sessionid, wanted, hash, sizeof(string));
    return !strcmp(hash, given);
}

namespace auth
{
    int lastlocalconnect = 0, lastlocalactivity = 0;
    uint nextlocalauthreq = 1;

    int lastconnect = 0, lastactivity = 0;
    uint nextauthreq = 1;

    clientinfo *findauth(uint id)
    {
        loopv(clients) if(clients[i]->authreq == id) return clients[i];
        loopv(connects) if(connects[i]->authreq == id) return connects[i];
        return NULL;
    }
    
    clientinfo *findlocalauth(uint id)
    {
        loopv(clients) if(clients[i]->localauthreq == id) return clients[i];
        loopv(connects) if(connects[i]->localauthreq == id) return connects[i];
        return NULL;
    }

    void reqauth(clientinfo *ci)
    {
        if(!nextauthreq) nextauthreq = 1;
        ci->authreq = nextauthreq++;
        requestmasterf("reqauth %u %s\n", ci->authreq, ci->authname);
        lastactivity = totalmillis;
        srvmsgft(ci->clientnum, CON_EVENT, "\fyplease wait, requesting credential match..");
    }

    void reqlocalauth(clientinfo *ci)
    {
        if(!nextlocalauthreq) nextlocalauthreq = 1;
        ci->localauthreq = nextlocalauthreq++;
        requestlocalmasterf("reqauth %u %s\n", ci->localauthreq, ci->localauthname);
        lastlocalactivity = totalmillis;
        srvmsgft(ci->clientnum, CON_EVENT, "\fyplease wait, requesting local credential match..");
    }

    bool tryauth(clientinfo *ci, const char *user)
    {
        if(!ci) return false;
        else if(!connectedmaster())
        {
            srvmsgft(ci->clientnum, CON_EVENT, "\founable to verify, not connected to master server");
            return false;
        }
        else if(ci->authreq)
        {
            srvmsgft(ci->clientnum, CON_EVENT, "\foplease wait, still processing previous attempt..");
            return true;
        }
        filtertext(ci->authname, user, true, true, false, 100);
        reqauth(ci);
        return true;
    }
    
    bool trylocalauth(clientinfo *ci, const char *user)
    {
        if(!ci) return false;
        else if(!connectedlocalmaster())
        {
            srvmsgft(ci->clientnum, CON_EVENT, "\founable to verify, not connected to local master server");
            return false;
        }
        else if(ci->localauthreq)
        {
            srvmsgft(ci->clientnum, CON_EVENT, "\foplease wait, still processing previous attempt..");
            return true;
        }
        filtertext(ci->localauthname, user, true, true, false, 100);
        reqlocalauth(ci);
        return true;
    }

    void setprivilege(clientinfo *ci, bool val, int flags = 0, bool authed = false, bool local = false)
    {
        int privilege = ci->privilege;
        if(val)
        {
            if(ci->privilege >= flags) return;
            privilege = ci->privilege = flags;
            if(authed)
            {
                if(ci->privilege > PRIV_PLAYER) srvoutforce(ci, -2, "\fy%s identified as \fs\fc%s\fS with \fs\fc%s\fS privileges", colorname(ci), local ? ci->localauthname : ci->authname, privname(privilege, false));
                else srvoutforce(ci, -2, "\fy%s identified as \fs\fc%s\fS", colorname(ci), local ? ci->localauthname : ci->authname);
            }
            else srvoutforce(ci, -2, "\fy%s elevated to \fs\fc%s\fS", colorname(ci), privname(privilege));
        }
        else
        {
            if(!ci->privilege) return;
            ci->privilege = PRIV_NONE;
            int others = 0;
            loopv(clients) if(clients[i]->privilege >= PRIV_HELPER || clients[i]->local) others++;
            if(!others) mastermode = MM_OPEN;
            srvoutforce(ci, -2, "\fy%s is no longer \fs\fc%s\fS", colorname(ci), privname(privilege));
        }
        privupdate = true;
        if(paused)
        {
            int others = 0;
            loopv(clients) if(clients[i]->privilege >= PRIV_ADMINISTRATOR || clients[i]->local) others++;
            if(!others) setpause(false);
        }
    }

    int allowconnect(clientinfo *ci, bool connecting = true, const char *pwd = "", const char *authname = "")
    {
        if(ci->local) return DISC_NONE;
        if(m_local(gamemode)) return DISC_PRIVATE;
        if(ci->privilege >= PRIV_MODERATOR) return DISC_NONE;
        if(*authname)
        {
            if(ci->connectauth) return DISC_NONE;
            if (strchr(authname, '@'))
            {
                if(trylocalauth(ci, authname))
                {
                    ci->connectauth = true;
                    return DISC_NONE;
                }
            }
            else
            {
                if(tryauth(ci, authname))
                {
                    ci->connectauth = true;
                    return DISC_NONE;
                }
            }
        }
        if(*pwd)
        {
            if(adminpass[0] && checkpassword(ci, adminpass, pwd))
            {
                if(GAME(autoadmin)) setprivilege(ci, true, PRIV_ADMINISTRATOR);
                return DISC_NONE;
            }
            if(serverpass[0] && checkpassword(ci, serverpass, pwd)) return DISC_NONE;
        }
        if(numclients() >= GAME(serverclients)) return DISC_MAXCLIENTS;
        uint ip = getclientip(ci->clientnum);
        if(!ci->privilege && !checkipinfo(control, ipinfo::ALLOW, ip))
        {
            if(mastermode >= MM_PRIVATE || serverpass[0]) return DISC_PRIVATE;
            if(checkipinfo(control, ipinfo::BAN, ip)) return DISC_IPBAN;
        }
        return DISC_NONE;
    }

    void authfailed(uint id)
    {
        clientinfo *ci = findauth(id);
        if(!ci) return;
        ci->authreq = ci->authname[0] = 0;
        srvmsgft(ci->clientnum, CON_EVENT, "\foauthority request failed, please check your credentials");
        if(ci->connectauth)
        {
            ci->connectauth = false;
            int disc = allowconnect(ci, false);
            if(disc) { disconnect_client(ci->clientnum, disc); return; }
            connected(ci);
        }
    }

    void authsucceeded(uint id, const char *name, const char *flags)
    {
        clientinfo *ci = findauth(id);
        if(!ci) return;
        ci->authreq = 0;
        int n = PRIV_NONE;
        for(const char *c = flags; *c; c++) switch(*c)
        {
            case 'a': n = PRIV_ADMINISTRATOR; break;
            case 'm': n = PRIV_MODERATOR; break;
            case 'h': n = PRIV_HELPER; break;
            case 'u': n = PRIV_PLAYER; break;
        }
        if(n > PRIV_NONE) setprivilege(ci, true, n, true);
        else ci->authname[0] = 0;
        if(ci->connectauth)
        {
            ci->connectauth = false;
            int disc = allowconnect(ci, false);
            if(disc) { disconnect_client(ci->clientnum, disc); return; }
            connected(ci);
        }
    }

    void authchallenged(uint id, const char *val)
    {
        clientinfo *ci = findauth(id);
        if(!ci) return;
        sendf(ci->clientnum, 1, "riis", N_AUTHCHAL, id, val);
    }
    
    void localauthfailed(uint id)
    {
        clientinfo *ci = findlocalauth(id);
        if(!ci) return;
        ci->localauthreq = ci->localauthname[0] = 0;
        srvmsgft(ci->clientnum, CON_EVENT, "\folocal authority request failed, please check your credentials");
        if(ci->connectauth)
        {
            ci->connectauth = false;
            int disc = allowconnect(ci, false);
            if(disc) { disconnect_client(ci->clientnum, disc); return; }
            connected(ci);
        }
    }

    void localauthsucceeded(uint id, int uid, const char *name, vector<char*> groups)
    {
        clientinfo *ci = findlocalauth(id);
        if(!ci) return;
        ci->localauthreq = 0;
        
        loopv(groups) ci->groups.add(newstring(groups[i]));
        ci->uid = uid;
        filtertext(ci->localauthname, name, true, true, false, 100);
        
        srvoutforce(ci, -2, "%s \fs\f0has verified.\fr", colorname(ci));
        
        if(ci->connectauth)
        {
            ci->connectauth = false;
            int disc = allowconnect(ci, false);
            if(disc) { disconnect_client(ci->clientnum, disc); return; }
            connected(ci);
        }
    }

    void localauthchallenged(uint id, const char *val)
    {
        clientinfo *ci = findlocalauth(id);
        if(!ci) return;
        sendf(ci->clientnum, 1, "riis", N_AUTHCHAL, id, val);
    }

    void answerchallenge(clientinfo *ci, uint id, char *val)
    {
        if(ci->authreq == id)
        {
            for(char *s = val; *s; s++)
            {
                if(!isxdigit(*s)) { *s = '\0'; break; }
            }
            requestmasterf("confauth %u %s\n", id, val);
            lastactivity = totalmillis;
        }
        else if (ci->localauthreq == id)
        {
            for(char *s = val; *s; s++)
            {
                if(!isxdigit(*s)) { *s = '\0'; break; }
            }
            requestlocalmasterf("confauth %u %s\n", id, val);
            lastlocalactivity = totalmillis;
        }
    }

    void processinput(const char *p)
    {
        const int MAXWORDS = 8;
        char *w[MAXWORDS];
        int numargs = MAXWORDS;
        loopi(MAXWORDS)
        {
            w[i] = (char *)"";
            if(i > numargs) continue;
            char *s = parsetext(p);
            if(s) w[i] = s;
            else numargs = i;
        }
        if(!strcmp(w[0], "error")) conoutf("master server error: %s", w[1]);
        else if(!strcmp(w[0], "echo")) conoutf("master server reply: %s", w[1]);
        else if(!strcmp(w[0], "failauth")) authfailed((uint)(atoi(w[1])));
        else if(!strcmp(w[0], "succauth")) authsucceeded((uint)(atoi(w[1])), w[2], w[3]);
        else if(!strcmp(w[0], "chalauth")) authchallenged((uint)(atoi(w[1])), w[2]);
        else loopj(ipinfo::MAXTYPES) if(!strcmp(w[0], ipinfotypes[j]))
        {
            ipinfo &p = control.add();
            p.ip = uint(atoi(w[1]));
            p.mask = uint(atoi(w[2]));
            p.type = j;
            p.flag = ipinfo::GLOBAL; // master info
            p.time = totalmillis ? totalmillis : 1;
            updatecontrols = true;
            break;
        }
        loopj(numargs) if(w[j]) delete[] w[j];
    }
    
    struct name_entry
    {
        char *name;
        char *date;
        int count;
    };
    
    void namesresult(uint id, vector<char*> names)
    {
        clientinfo *ci = findlocalauth(id);
        if(!ci) return;
        
        int total_occurances = 0;
        vector<name_entry*> name_entries;
        
        for(int i = 0; i+2 < names.length(); i+=3)
        {
            int occurances = atoi(names[i+2]);
            total_occurances += occurances;
            name_entry *ne = new name_entry;
            ne->name = names[i];
            ne->date = names[i+1];
            ne->count = occurances;
            name_entries.put(ne);
        }
        
        vector<char> names_output;
        
        loopv(name_entries)
        {
            string entry_str;
            name_entry *ne = name_entries[i];
            formatstring(entry_str)(" %s(%d, %.2f%%, %s)", ne->name, ne->count, float(ne->count)*100.0/float(total_occurances), ne->date);
            names_output.put(entry_str, strlen(entry_str));
        }
        
        srvmsgft(ci->clientnum, CON_EVENT, "\fs\f1Info:\fr Names:%s", names_output.getbuf());
    }
    
    void namesrequest(clientinfo *ci, uint ip, uint mask)
    {
        if(!nextlocalauthreq) nextlocalauthreq = 1;
        ci->localauthreq = nextlocalauthreq++;
        
        if(!requestlocalmasterf("names %u %u %u\n", ci->localauthreq, ip, mask))
        {
            sendf(ci->clientnum, 1, "ris", N_SERVMSG, "not connected to local master server.");
        }
    }
    
    void effectupdated(punitiveeffects::punitiveeffect* effect)
    {
        loopv(clients)
        {
            clientinfo *ci = clients[i];
            uint ip = getclientip(ci->clientnum);
            if(((effect->ip & effect->mask) == (ip & effect->mask)))
            {
                const char* effect_type = punitiveeffects::type_name(effect->type, true);
                srvmsgf(ci->clientnum, "\fs\f1Info:\fr You are now \fs\f3%s\fr for \"\fs\f4%s\fr\".", effect_type, effect->reason);
                if(!(ci->privilege || ci->local || hasmastergroup(ci) || hasadmingroup(ci)))
                {
                    if(effect->type==punitiveeffects::BAN) disconnect_client(ci->clientnum, DISC_IPBAN);
                    if(effect->type==punitiveeffects::SPECTATE && ci->state.state!=CS_SPECTATOR) spectate(ci, true);
                }
            }
        }
    }

    void effectremoved(punitiveeffects::punitiveeffect* effect)
    {
        loopv(clients)
        {
            clientinfo *ci = clients[i];
            uint ip = getclientip(ci->clientnum);
            if(((effect->ip & effect->mask) == (ip & effect->mask)))
            {
                const char* effect_type = punitiveeffects::type_name(effect->type, true);
                srvmsgf(ci->clientnum, "\fs\f1Info:\fr You are no longer \fs\f3%s\fr for \"\fs\f4%s\fr\".", effect_type, effect->reason);
            }
        }
    }

    void processlocalinput(const char *p)
    {
        fprintf(stderr, "started processlocalinput.\n");
    
        vector<char*> w;
        explodelist(p, w);
        
        uint id, ip, mask;
		string val;
		int pos;

        if(!strcmp(w[0], "error")) conoutf("master server error: %s", w[1]);
        else if(!strcmp(w[0], "echo")) conoutf("master server reply: %s", w[1]);
        else if(!strcmp(w[0], "failauth")) localauthfailed((uint)(atoi(w[1])));
        else if(!strcmp(w[0], "succauth"))
        {
            uint reqid = (uint)(atoi(w[1]));
            int uid = atoi(w[2]);
            char *name = w[3];
            w.remove(0, 4); // Remove the stuff before the groups
            localauthsucceeded(reqid, uid, name, w);
        }
        else if(!strcmp(w[0], "chalauth")) localauthchallenged((uint)(atoi(w[1])), w[2]);
        else if(!strcmp(w[0], "names"))
        {
            uint reqid = (uint)(atoi(w[1]));
            w.remove(0, 2); // Remove the stuff before the names
            namesresult(reqid, w);
        }
        else if(sscanf(p, "effectupdate %u %s %u %u %n", &id, val, &ip, &mask, &pos) == 4)
        {
            punitiveeffects::punitiveeffect* effect = punitiveeffects::update(id, ip, mask, punitiveeffects::type_id(val), &p[pos]);
            effectupdated(effect);
        }
        else if(sscanf(p, "effectremove %u", &id) == 1)
        {
            punitiveeffects::punitiveeffect* effect = punitiveeffects::remove(id);
            if(effect)
            {
                effectremoved(effect);
                free(effect->reason);
                free(effect);
            }
        }
        else loopj(ipinfo::MAXTYPES) if(!strcmp(w[0], ipinfotypes[j]))
        {
            ipinfo &p = control.add();
            p.ip = uint(atoi(w[1]));
            p.mask = uint(atoi(w[2]));
            p.type = j;
            p.flag = ipinfo::GLOBAL; // master info
            p.time = totalmillis ? totalmillis : 1;
            updatecontrols = true;
            break;
        }
        
        fprintf(stderr, "got to the end of processlocalinput.\n");
    }

    void regserver()
    {
        loopvrev(control) if(control[i].flag == ipinfo::GLOBAL) control.remove(i);
        conoutf("updating master server");
        requestmasterf("server %d\n", serverport);
        lastactivity = totalmillis;
    }
    
    void reglocalserver()
    {
        conoutf("updating local master server");
        requestlocalmasterf("regserv %d\n", serverport);
        lastlocalactivity = totalmillis;
    }

    void update()
    {
        if(servertype < 2)
        {
            if(connectedmaster()) disconnectmaster();
            if(connectedlocalmaster()) disconnectlocalmaster();
            return;
        }
        else
        {
            if(!connectedmaster() && (!lastconnect || totalmillis-lastconnect > 60*1000))
            {
                lastconnect = totalmillis;
                if(connectmaster() != ENET_SOCKET_NULL)
                {
                    regserver();
                    loopv(clients) if(clients[i]->authreq) reqauth(clients[i]);
                }
            }
            
            if(!connectedlocalmaster() && (!lastlocalconnect || totalmillis-lastlocalconnect > 60*1000))
            {
                lastlocalconnect = totalmillis;
                if(connectlocalmaster() != ENET_SOCKET_NULL)
                {
                    reglocalserver();
                    loopv(clients) if(clients[i]->localauthreq) reqlocalauth(clients[i]);
                }
            }
        }

        if(totalmillis-lastactivity > 30*60*1000) regserver();
        if(totalmillis-lastlocalactivity > 30*60*1000) reglocalserver();
    }
}

void disconnectedmaster()
{
}

void disconnectedlocalmaster()
{
}

void processmasterinput(const char *cmd, int cmdlen, const char *args)
{
    auth::processinput(cmd);
}

void processlocalmasterinput(const char *cmd, int cmdlen, const char *args)
{
    auth::processlocalinput(cmd);
}
