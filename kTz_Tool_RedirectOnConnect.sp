#include <sourcemod>
#include <sdktools>
#include <dhooks>
#include <clientprefs>

/* =========================================
  =========================================
  =======          Net API          =======
 ========================================= 
========================================= */

#define A2S_GETCHALLENGE    'q'

enum netadrtype_t
{ 
    NA_NULL = 0,
    NA_LOOPBACK,
    NA_BROADCAST,
    NA_IP,
}

enum struct netadr_s_offsets
{
    int type;
    int ip;
    int port;
}

enum struct netpacket_t_offsets
{
    int from;
    //...
    int data;
    //...
    int size;
    //...
}

enum struct NetOffsets
{
    netadr_s_offsets nao;
    netpacket_t_offsets npo;
}
static NetOffsets offsets;

methodmap AddressBase
{
    property Address Address
    {
        public get() { return view_as<Address>(this); }
    }
}

methodmap Netadr_s < AddressBase
{
    property netadrtype_t type
    {
        public get() { return view_as<netadrtype_t>(LoadFromAddress(this.Address + offsets.nao.type, NumberType_Int32)); }
    }
    
    property int ip
    {
        public get() { return LoadFromAddress(this.Address + offsets.nao.ip, NumberType_Int32); }
    }
    
    property int port
    {
        public get() { return LoadFromAddress(this.Address + offsets.nao.port, NumberType_Int16); }
    }
    
    public void ToString(char[] buff, int size)
    {
        int ip = this.ip;
        Format(buff, size, "%i.%i.%i.%i", ip & 0xFF, ip >> 8 & 0xFF, ip >> 16 & 0xFF, ip >>> 24);
    }
}

methodmap Netpacket_t < AddressBase
{
    property Netadr_s from
    {
        public get() { return view_as<Netadr_s>(this.Address + offsets.npo.from); }
    }
    
    //...
    
    property Address data
    {
        public get() { return view_as<Address>(LoadFromAddress(this.Address + offsets.npo.data, NumberType_Int32)); }
    }
    
    //...
    
    property int size
    {
        public get() { return LoadFromAddress(this.Address + offsets.npo.size, NumberType_Int32); }
    }
    
    //...
}

stock void InitNet(GameData gd)
{
    char buff[128];

    //netadr_s
    if (!(gd.GetKeyValue("netadr_s::type", buff, sizeof(buff))))
        SetFailState("Can't get \"netadr_s::type\" offset from gamedata.");
    offsets.nao.type = StringToInt(buff);

    if (!(gd.GetKeyValue("netadr_s::ip", buff, sizeof(buff))))
        SetFailState("Can't get \"netadr_s::ip\" offset from gamedata.");
    offsets.nao.ip = StringToInt(buff);

    if (!(gd.GetKeyValue("netadr_s::port", buff, sizeof(buff))))
        SetFailState("Can't get \"netadr_s::port\" offset from gamedata.");
    offsets.nao.port = StringToInt(buff);

    //netpacket_t
    if (!(gd.GetKeyValue("netpacket_t::from", buff, sizeof(buff))))
        SetFailState("Can't get \"netpacket_t::from\" offset from gamedata.");
    offsets.npo.from = StringToInt(buff);

    offsets.npo.data = gd.GetOffset("netpacket_t::data");
    if (offsets.npo.data == -1)
        SetFailState("Can't get \"netpacket_t::data\" offset from gamedata");

    offsets.npo.size = gd.GetOffset("netpacket_t::size");
    if (offsets.npo.size == -1)
        SetFailState("Can't get \"netpacket_t::size\" offset from gamedata");
}

/* =========================================
  =========================================
  =======          Net API          =======
 ========================================= 
========================================= */

#pragma semicolon 1
#pragma newdecls required

#define LoopAllPlayers(%1) for(int %1=1;%1<=MaxClients;++%1)\
if(IsPlayerExist(%1))

ConVar g_cvar_TargetServer;
Handle g_h_RejectConnection;

public Plugin myinfo = 
{
    name = "Force Redirect",
    author = "Kroytz",
    description = "",
    version = "1.33.7",
    url = ""
};

public void OnPluginStart()
{
    GameData gd = new GameData("server_redirect.games");
    if(gd == null)
        SetFailState("Why you have no gamedata?");

    InitNet(gd);
    SetupSDKCalls(gd);
    SetupDhooks(gd);

    g_cvar_TargetServer = CreateConVar("rd_target_server", "127.0.0.1:27015", "Target server of redirect");
}

void SetupSDKCalls(GameData gd)
{
    //CBaseServer::RejectConnection
    StartPrepSDKCall(SDKCall_Static);

    if (!PrepSDKCall_SetFromConf(gd, SDKConf_Signature, "CBaseServer::RejectConnection"))
        SetFailState("Can't get offset for \"CBaseServer::RejectConnection\".");

    PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
    PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
    PrepSDKCall_AddParameter(SDKType_String, SDKPass_Pointer);

    g_h_RejectConnection = EndPrepSDKCall();
    if (!g_h_RejectConnection)
        SetFailState("Failed to create SDKCall to \"CBaseServer::RejectConnection\".");
}

void SetupDhooks(GameData gd)
{
    //CBaseServer::ProcessConnectionlessPacket
    Handle dhook = DHookCreateDetour(Address_Null, CallConv_THISCALL, ReturnType_Bool, ThisPointer_Address);

    DHookSetFromConf(dhook, gd, SDKConf_Signature, "CBaseServer::ProcessConnectionlessPacket");
    if (!dhook)
        SetFailState("Can't find \"CBaseServer::ProcessConnectionlessPacket\" signature.");
    DHookAddParam(dhook, HookParamType_Int);

    if (!DHookEnableDetour(dhook, false, ProcessConnectionlessPacket_Dhook))
        SetFailState("Can't enable detour for \"CBaseServer::ProcessConnectionlessPacket\".");
}

public MRESReturn ProcessConnectionlessPacket_Dhook(Address pThis, Handle hReturn, Handle hParams)
{
    Netpacket_t packet = DHookGetParam(hParams, 1);

    if (packet.size < 5)
        return MRES_Ignored;

    if (LoadFromAddress(packet.data + 4, NumberType_Int8) != A2S_GETCHALLENGE)
        return MRES_Ignored;

    Netadr_s from = packet.from;

    if(from.type != NA_IP)
        return MRES_Ignored;

    char szTarget[64];
    g_cvar_TargetServer.GetString(szTarget, sizeof(szTarget));
    RejectConnection(pThis, packet, "ConnectRedirectAddress:%s", szTarget);

    DHookSetReturn(hReturn, 1);
    return MRES_Supercede;
}

stock void RejectConnection(Address pThis, Netpacket_t packet, const char[] reject_msg, any ...)
{
    char buff[64];
    VFormat(buff, sizeof(buff), reject_msg, 4);
    SDKCall(g_h_RejectConnection, pThis, packet, buff);
}

stock bool IsPlayerExist(int client)
{
    // If client isn't valid, then stop
    if (client <= 0 || client > MaxClients)
    {
        return false;
    }

    // If client isn't connected, then stop
    if (!IsClientConnected(client))
    {
        return false;
    }

    // If client isn't in game, then stop
    if (!IsClientInGame(client) || IsClientInKickQueue(client))
    {
        return false;
    }

    // If client is TV, then stop
    if (IsClientSourceTV(client))
    {
        return false;
    }

    if (IsFakeClient(client))
    {
        return false;
    }

    // If client exist
    return true;
}