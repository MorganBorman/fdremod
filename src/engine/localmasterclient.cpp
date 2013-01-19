static ENetSocket localmastersock = ENET_SOCKET_NULL;
ENetAddress localmasteraddress = { ENET_HOST_ANY, ENET_PORT_ANY };
static vector<char> localmasterout, localmasterin;
static int localmasteroutpos = 0, localmasterinpos = 0;

void disconnectlocalmaster()
{
    if(localmastersock != ENET_SOCKET_NULL)
    {
        server::disconnectedlocalmaster();
        enet_socket_destroy(localmastersock);
        localmastersock = ENET_SOCKET_NULL;
        conoutf("disconnected from local master server");
    }

    localmasterout.setsize(0);
    localmasterin.setsize(0);
    localmasteroutpos = localmasterinpos = 0;

    localmasteraddress.host = ENET_HOST_ANY;
    localmasteraddress.port = ENET_PORT_ANY;
}

VARF(0, serverlocalmasterport, 1, RE_MASTER_PORT, INT_MAX-1, disconnectlocalmaster());
SVARF(0, serverlocalmaster, RE_MASTER_HOST, disconnectlocalmaster());

ENetSocket connectlocalmaster(bool reuse)
{
    if(reuse && localmastersock != ENET_SOCKET_NULL) return localmastersock;
    if(!serverlocalmaster[0]) return ENET_SOCKET_NULL;

    if(localmasteraddress.host == ENET_HOST_ANY)
    {
        conoutf("\falooking up %s:[%d]...", serverlocalmaster, serverlocalmasterport);
        localmasteraddress.port = serverlocalmasterport;
        if(!resolverwait(serverlocalmaster, &localmasteraddress))
        {
            conoutf("\frfailed resolving %s:[%d]", serverlocalmaster, serverlocalmasterport);
            return ENET_SOCKET_NULL;
        }
    }
    ENetSocket sock = enet_socket_create(ENET_SOCKET_TYPE_STREAM);
    if(sock != ENET_SOCKET_NULL && serveraddress.host != ENET_HOST_ANY && enet_socket_bind(sock, &serveraddress) < 0)
    {
        enet_socket_destroy(sock);
        sock = ENET_SOCKET_NULL;
    }
    if(sock == ENET_SOCKET_NULL || connectwithtimeout(sock, serverlocalmaster, localmasteraddress) < 0)
    {
        conoutf(sock==ENET_SOCKET_NULL ? "\frcould not open socket to connect to local master server" : "\frcould not connect to local master server");
        return ENET_SOCKET_NULL;
    }

    enet_socket_set_option(sock, ENET_SOCKOPT_NONBLOCK, 1);
    if(reuse) localmastersock = sock;
    return sock;
}

bool connectedlocalmaster() { return localmastersock != ENET_SOCKET_NULL; }

bool requestlocalmaster(const char *req)
{
    if(localmastersock == ENET_SOCKET_NULL)
    {
        localmastersock = connectlocalmaster();
        if(localmastersock == ENET_SOCKET_NULL) return false;
    }

    localmasterout.put(req, strlen(req));
    return true;
}

bool requestlocalmasterf(const char *fmt, ...)
{
    defvformatstring(req, fmt, fmt);
    return requestlocalmaster(req);
}

void processlocalmasterinput()
{
    if(localmasterinpos >= localmasterin.length()) return;

    char *input = &localmasterin[localmasterinpos], *end = (char *)memchr(input, '\n', localmasterin.length() - localmasterinpos);
    while(end)
    {
        *end++ = '\0';

        const char *args = input;
        while(args < end && !iscubespace(*args)) args++;
        int cmdlen = args - input;
        while(args < end && iscubespace(*args)) args++;

        server::processlocalmasterinput(input, cmdlen, args);

        localmasterinpos = end - localmasterin.getbuf();
        input = end;
        end = (char *)memchr(input, '\n', localmasterin.length() - localmasterinpos);
    }

    if(localmasterinpos >= localmasterin.length())
    {
        localmasterin.setsize(0);
        localmasterinpos = 0;
    }
}

void flushlocalmasteroutput()
{
    if(localmasterout.empty()) return;

    ENetBuffer buf;
    buf.data = &localmasterout[localmasteroutpos];
    buf.dataLength = localmasterout.length() - localmasteroutpos;
    int sent = enet_socket_send(localmastersock, NULL, &buf, 1);
    if(sent >= 0)
    {
        localmasteroutpos += sent;
        if(localmasteroutpos >= localmasterout.length())
        {
            localmasterout.setsize(0);
            localmasteroutpos = 0;
        }
    }
    else disconnectlocalmaster();
}

void flushlocalmasterinput()
{
    if(localmasterin.length() >= localmasterin.capacity())
        localmasterin.reserve(4096);

    ENetBuffer buf;
    buf.data = localmasterin.getbuf() + localmasterin.length();
    buf.dataLength = localmasterin.capacity() - localmasterin.length();
    int recv = enet_socket_receive(localmastersock, NULL, &buf, 1);
    if(recv > 0)
    {
        localmasterin.advance(recv);
        processlocalmasterinput();
    }
    else disconnectlocalmaster();
}
