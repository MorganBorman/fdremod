static ENetSocket mastersock = ENET_SOCKET_NULL;
ENetAddress masteraddress = { ENET_HOST_ANY, ENET_PORT_ANY };
static vector<char> masterout, masterin;
static int masteroutpos = 0, masterinpos = 0;

void disconnectmaster()
{
    if(mastersock != ENET_SOCKET_NULL)
    {
        server::disconnectedmaster();
        enet_socket_destroy(mastersock);
        mastersock = ENET_SOCKET_NULL;
        conoutf("disconnected from master server");
    }

    masterout.setsize(0);
    masterin.setsize(0);
    masteroutpos = masterinpos = 0;

    masteraddress.host = ENET_HOST_ANY;
    masteraddress.port = ENET_PORT_ANY;
}

VARF(0, servermasterport, 1, RE_MASTER_PORT, INT_MAX-1, disconnectmaster());
SVARF(0, servermaster, RE_MASTER_HOST, disconnectmaster());

ENetSocket connectmaster(bool reuse)
{
    if(reuse && mastersock != ENET_SOCKET_NULL) return mastersock;
    if(!servermaster[0]) return ENET_SOCKET_NULL;

    if(masteraddress.host == ENET_HOST_ANY)
    {
        conoutf("\falooking up %s:[%d]...", servermaster, servermasterport);
        masteraddress.port = servermasterport;
        if(!resolverwait(servermaster, &masteraddress))
        {
            conoutf("\frfailed resolving %s:[%d]", servermaster, servermasterport);
            return ENET_SOCKET_NULL;
        }
    }
    ENetSocket sock = enet_socket_create(ENET_SOCKET_TYPE_STREAM);
    if(sock != ENET_SOCKET_NULL && serveraddress.host != ENET_HOST_ANY && enet_socket_bind(sock, &serveraddress) < 0)
    {
        enet_socket_destroy(sock);
        sock = ENET_SOCKET_NULL;
    }
    if(sock == ENET_SOCKET_NULL || connectwithtimeout(sock, servermaster, masteraddress) < 0)
    {
        conoutf(sock==ENET_SOCKET_NULL ? "\frcould not open socket to connect to master server" : "\frcould not connect to master server");
        return ENET_SOCKET_NULL;
    }

    enet_socket_set_option(sock, ENET_SOCKOPT_NONBLOCK, 1);
    if(reuse) mastersock = sock;
    return sock;
}

bool connectedmaster() { return mastersock != ENET_SOCKET_NULL; }

bool requestmaster(const char *req)
{
    if(mastersock == ENET_SOCKET_NULL)
    {
        mastersock = connectmaster();
        if(mastersock == ENET_SOCKET_NULL) return false;
    }

    masterout.put(req, strlen(req));
    return true;
}

bool requestmasterf(const char *fmt, ...)
{
    defvformatstring(req, fmt, fmt);
    return requestmaster(req);
}

void processmasterinput()
{
    if(masterinpos >= masterin.length()) return;

    char *input = &masterin[masterinpos], *end = (char *)memchr(input, '\n', masterin.length() - masterinpos);
    while(end)
    {
        *end++ = '\0';

        const char *args = input;
        while(args < end && !iscubespace(*args)) args++;
        int cmdlen = args - input;
        while(args < end && iscubespace(*args)) args++;

        server::processmasterinput(input, cmdlen, args);

        masterinpos = end - masterin.getbuf();
        input = end;
        end = (char *)memchr(input, '\n', masterin.length() - masterinpos);
    }

    if(masterinpos >= masterin.length())
    {
        masterin.setsize(0);
        masterinpos = 0;
    }
}

void flushmasteroutput()
{
    if(masterout.empty()) return;

    ENetBuffer buf;
    buf.data = &masterout[masteroutpos];
    buf.dataLength = masterout.length() - masteroutpos;
    int sent = enet_socket_send(mastersock, NULL, &buf, 1);
    if(sent >= 0)
    {
        masteroutpos += sent;
        if(masteroutpos >= masterout.length())
        {
            masterout.setsize(0);
            masteroutpos = 0;
        }
    }
    else disconnectmaster();
}

void flushmasterinput()
{
    if(masterin.length() >= masterin.capacity())
        masterin.reserve(4096);

    ENetBuffer buf;
    buf.data = masterin.getbuf() + masterin.length();
    buf.dataLength = masterin.capacity() - masterin.length();
    int recv = enet_socket_receive(mastersock, NULL, &buf, 1);
    if(recv > 0)
    {
        masterin.advance(recv);
        processmasterinput();
    }
    else disconnectmaster();
}
