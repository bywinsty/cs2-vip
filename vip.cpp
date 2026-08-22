#include <stdio.h>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <set>
#include <string_view>
#include <utility>
#include <vector>
#include "vip.h"
#include "include/vip_database_migration.h"
#include "metamod_oslink.h"
#include "schemasystem/schemasystem.h"

#ifndef VIP_BUILD_COMMIT
#define VIP_BUILD_COMMIT "local"
#endif

VIP g_VIP;
PLUGIN_EXPOSE(VIP, g_VIP);
IVEngineServer2* engine = nullptr;
CGameEntitySystem* g_pGameEntitySystem = nullptr;
CEntitySystem* g_pEntitySystem = nullptr;
CCSGameRules* g_pGameRules = nullptr;

std::map<std::string, std::map<std::string,std::string>> g_VipGroups;
std::map<uint64, VipPlayer> g_VipPlayer;
std::map<std::string, VIPFunctions> g_VipFunctions;

std::map<std::string, std::string> g_pKVUser[64];
KeyValues* g_hKVData;

const char* RuntimeProbeNonce()
{
	const char* enabled = std::getenv("VIP_CI_RUNTIME_PROBE");
	const char* nonce = std::getenv("VIP_CI_RUNTIME_NONCE");
	if (!enabled || std::strcmp(enabled, "1") != 0 || !nonce || std::strlen(nonce) != 32)
		return nullptr;
	for (const char* character = nonce; *character; ++character)
	{
		if (!std::isxdigit(static_cast<unsigned char>(*character)))
			return nullptr;
	}
	return nonce;
}

void EmitRuntimeInterfaceProbe()
{
	const char* nonce = RuntimeProbeNonce();
	if (!nonce)
		return;
	int legacyResult = META_IFACE_FAILED;
	int v2Result = META_IFACE_FAILED;
	const bool legacy = g_SMAPI->MetaFactory(VIP_INTERFACE_LEGACY, &legacyResult, nullptr) != nullptr && legacyResult != META_IFACE_FAILED;
	const bool v2 = g_SMAPI->MetaFactory(VIP_INTERFACE_V2, &v2Result, nullptr) != nullptr && v2Result != META_IFACE_FAILED;
	ConColorMsg(Color(0, 255, 127, 255),
		"[VIP-CI] {\"event\":\"interfaces\",\"nonce\":\"%s\",\"legacy\":%s,\"v2\":%s}\n",
		nonce, legacy ? "true" : "false", v2 ? "true" : "false");
}

void EmitRuntimeReadyProbe()
{
	const char* nonce = RuntimeProbeNonce();
	if (!nonce)
		return;
	ConColorMsg(Color(0, 255, 127, 255),
		"[VIP-CI] {\"event\":\"core_ready\",\"nonce\":\"%s\",\"ready\":true,\"version\":\"%s\",\"build_commit\":\"%s\"}\n",
		nonce, g_PLAPI->GetVersion(), VIP_BUILD_COMMIT);
}

void MigrateLegacyClientData(uint64 steamID)
{
	if (!g_hKVData || steamID == 0)
		return;

	const std::string currentKey = std::to_string(steamID);
	if (g_hKVData->FindKey(currentKey.c_str(), false))
		return;

	const std::string legacyKey = std::to_string(static_cast<uint32>(steamID));
	KeyValues *legacyData = g_hKVData->FindKey(legacyKey.c_str(), false);
	if (!legacyData)
		return;

	KeyValues *currentData = g_hKVData->FindKey(currentKey.c_str(), true);
	FOR_EACH_VALUE(legacyData, pValue)
		currentData->SetString(pValue->GetName(), pValue->GetString(nullptr, nullptr));
	g_hKVData->SaveToFile(g_pFullFileSystem, "addons/data/vip_data.ini");
}

bool g_bPistolRound;
int m_iServerID;

IMySQLClient *g_pMysqlClient;
IMySQLConnection* g_pConnection;

enum class DatabaseState
{
	Disconnected,
	Connecting,
	Migrating,
	Ready,
	Failed,
};

DatabaseState g_databaseState = DatabaseState::Disconnected;
std::set<std::pair<int, uint64>> g_pendingClientAuthorizations;
bool g_migrationLockHeld = false;

bool DatabaseReady()
{
	return g_databaseState == DatabaseState::Ready && g_pConnection != nullptr;
}

IUtilsApi* g_pUtils;
IMenusApi* g_pMenus;
ICookiesApi* g_pCookies;
IPlayersApi* g_pPlayers;

std::map<std::string, std::string> g_vecPhrases;

VIPApi* g_pVIPApi = nullptr;
IVIPApi* g_pVIPCore = nullptr;

SH_DECL_HOOK3_void(IServerGameDLL, GameFrame, SH_NOATTRIB, 0, bool, bool, bool);
SH_DECL_HOOK4_void(IServerGameClients, ClientPutInServer, SH_NOATTRIB, 0, CPlayerSlot, char const*, int, uint64);
SH_DECL_HOOK5_void(IServerGameClients, ClientDisconnect, SH_NOATTRIB, 0, CPlayerSlot, ENetworkDisconnectionReason, const char *, uint64, const char *);

CGameEntitySystem* GameEntitySystem()
{
	return g_pUtils->GetCGameEntitySystem();
};

bool ParseNumericArgument(const char *value, uint64 &result)
{
	if (!value)
		return false;
	return vip_database::ParseUnsignedDecimal(std::string_view(value), result);
}

void LoadAuthorizedClient(int iSlot, uint64 steamID);

bool ReadFirstInteger(ISQLQuery *query, int &value)
{
	if (!query)
		return false;
	ISQLResult *result = query->GetResultSet();
	if (!result || !result->FetchRow())
		return false;
	value = result->GetInt(0);
	return true;
}

bool ReadColumnDescription(ISQLQuery *query, std::string &dataType, std::string &columnType)
{
	if (!query)
		return false;
	ISQLResult *result = query->GetResultSet();
	if (!result || !result->FetchRow())
		return false;
	const char *data = result->GetString(0);
	const char *column = result->GetString(1);
	if (!data || !column)
		return false;
	dataType = data;
	columnType = column;
	return true;
}

void FailDatabase(const char *stage, const std::string &detail);

void ReleaseMigrationLock(std::function<void()> continuation)
{
	if (!g_migrationLockHeld || !g_pConnection)
	{
		if (continuation)
			continuation();
		return;
	}
	g_migrationLockHeld = false;
	const auto plan = vip_database::BuildMigrationPlan();
	g_pConnection->ExecuteTransaction(
		Transaction{std::vector<std::string>{plan.releaseLockQuery}},
		[continuation](std::vector<ISQLQuery *> results) {
			int released = 0;
			if (!results.empty() && ReadFirstInteger(results.front(), released) && released == 1)
			{
				if (continuation)
					continuation();
				return;
			}
			if (g_databaseState == DatabaseState::Migrating)
				FailDatabase("release-lock", "RELEASE_LOCK did not release the migration lock");
		},
		[](std::string error, int queryIndex) {
			if (g_databaseState == DatabaseState::Migrating)
			{
				std::string detail = error.empty() ? "RELEASE_LOCK failed" : error;
				detail += " (query index " + std::to_string(queryIndex) + ")";
				FailDatabase("release-lock", detail);
			}
		});
}

void FailDatabase(const char *stage, const std::string &detail)
{
	if (g_databaseState == DatabaseState::Failed)
		return;
	g_databaseState = DatabaseState::Failed;
	if (g_pVIPApi)
		g_pVIPApi->SetReady(false);
	if (g_pVIPApi)
	{
		for (const auto &pending : g_pendingClientAuthorizations)
			g_pVIPApi->Call_VIP_OnClientLoaded(pending.first, false);
	}
	g_pendingClientAuthorizations.clear();
	if (g_pUtils)
		g_pUtils->ErrorLog("[VIP] Database migration failed at %s: %s", stage, detail.c_str());
	else
		META_CONPRINT("[VIP] Database migration failed\n");
	ReleaseMigrationLock(nullptr);
}

void RunMigrationTransaction(const char *stage, std::vector<std::string> queries,
	std::function<void(const std::vector<ISQLQuery *> &)> success)
{
	if (!g_pConnection || g_databaseState != DatabaseState::Migrating)
	{
		FailDatabase(stage, "database connection is not available");
		return;
	}
	g_pConnection->ExecuteTransaction(
		Transaction{std::move(queries)},
		[success](std::vector<ISQLQuery *> results) {
			if (g_databaseState != DatabaseState::Migrating)
				return;
			if (success)
				success(results);
		},
		[stage](std::string error, int queryIndex) {
			std::string detail = error.empty() ? "SQLMM transaction failed" : error;
			detail += " (query index " + std::to_string(queryIndex) + ")";
			FailDatabase(stage, detail);
		});
}

void FinishDatabaseMigration()
{
	ReleaseMigrationLock([] {
		if (g_databaseState != DatabaseState::Migrating)
			return;
		g_databaseState = DatabaseState::Ready;
		g_pVIPApi->SetReady(true);
		g_pVIPApi->Call_VIP_OnVIPLoaded();
		EmitRuntimeReadyProbe();
		const auto pending = g_pendingClientAuthorizations;
		g_pendingClientAuthorizations.clear();
		for (const auto &[slot, steamID] : pending)
			LoadAuthorizedClient(slot, steamID);
	});
}

void RecordMigrationVersion()
{
	const auto plan = vip_database::BuildMigrationPlan();
	RunMigrationTransaction("record-version", {plan.recordVersion}, [](const std::vector<ISQLQuery *> &) {
		FinishDatabaseMigration();
	});
}

void VerifyLegacyRows(vip_database::AccountColumnKind columnKind)
{
	const auto plan = vip_database::BuildMigrationPlan();
	RunMigrationTransaction("verify-normalized-ids", {plan.verifyLegacy, plan.warnUnmapped},
		[columnKind](const std::vector<ISQLQuery *> &results) {
			int remaining = 0;
			if (results.empty() || !ReadFirstInteger(results.front(), remaining))
			{
				FailDatabase("verify-normalized-ids", "verification result is missing");
				return;
			}
			if (remaining != 0)
			{
				FailDatabase("verify-normalized-ids", "legacy account IDs remain after normalization");
				return;
			}
			int unmapped = 0;
			if (results.size() < 2 || !ReadFirstInteger(results[1], unmapped))
			{
				FailDatabase("verify-normalized-ids", "unmapped-ID warning result is missing");
				return;
			}
			if (unmapped > 0 && g_pUtils)
				g_pUtils->ErrorLog("[VIP] Database migration retained %d account IDs outside the legacy/SteamID64 ranges", unmapped);
			const auto plan = vip_database::BuildMigrationPlan();
			if (columnKind != vip_database::AccountColumnKind::UnsignedBigInt)
			{
				RunMigrationTransaction("finalize-schema", {plan.finalizeUnsignedColumn}, [](const std::vector<ISQLQuery *> &) {
					RecordMigrationVersion();
				});
				return;
			}
			RecordMigrationVersion();
		});
}

void NormalizeLegacyRows(vip_database::AccountColumnKind columnKind)
{
	const auto plan = vip_database::BuildMigrationPlan();
	RunMigrationTransaction("normalize-legacy-ids",
		{plan.archiveConflicts[0], plan.archiveConflicts[1], plan.removeConflicts[0],
		 plan.removeConflicts[1], plan.normalizeLegacy},
		[columnKind](const std::vector<ISQLQuery *> &) {
			VerifyLegacyRows(columnKind);
		});
}

void InspectDatabaseSchema()
{
	RunMigrationTransaction(
		"inspect-schema",
		{"SELECT `DATA_TYPE`, `COLUMN_TYPE` FROM `INFORMATION_SCHEMA`.`COLUMNS` "
		 "WHERE `TABLE_SCHEMA` = DATABASE() AND `TABLE_NAME` = 'vip_users' "
		 "AND `COLUMN_NAME` = 'account_id';"},
		[](const std::vector<ISQLQuery *> &results) {
			std::string dataType;
			std::string columnType;
			if (results.empty() || !ReadColumnDescription(results.front(), dataType, columnType))
			{
				FailDatabase("inspect-schema", "account_id column is missing");
				return;
			}
			const auto kind = vip_database::ClassifyAccountColumn(dataType, columnType);
			if (kind == vip_database::AccountColumnKind::Unknown)
			{
				FailDatabase("inspect-schema", "unsupported account_id column type: " + columnType);
				return;
			}
			const auto plan = vip_database::BuildMigrationPlan();
			if (vip_database::IsLegacyWidth(kind))
			{
				RunMigrationTransaction("widen-signed-column", {plan.widenSignedColumn}, [kind](const std::vector<ISQLQuery *> &) {
					NormalizeLegacyRows(kind);
				});
				return;
			}
			if (kind == vip_database::AccountColumnKind::SignedBigInt)
			{
				NormalizeLegacyRows(kind);
				return;
			}
			NormalizeLegacyRows(kind);
		});
}

void StartDatabaseMigration()
{
	g_databaseState = DatabaseState::Migrating;
	const auto plan = vip_database::BuildMigrationPlan();
	RunMigrationTransaction("acquire-lock", {plan.lockQuery}, [](const std::vector<ISQLQuery *> &results) {
		int acquired = 0;
		if (results.empty() || !ReadFirstInteger(results.front(), acquired) || acquired != 1)
		{
			FailDatabase("acquire-lock", "another server owns the migration lock or GET_LOCK failed");
			return;
		}
		g_migrationLockHeld = true;
		const auto plan = vip_database::BuildMigrationPlan();
		RunMigrationTransaction("create-users-table", {plan.createUsers}, [plan](const std::vector<ISQLQuery *> &) {
			RunMigrationTransaction("create-migration-history", {plan.createHistory}, [plan](const std::vector<ISQLQuery *> &) {
				RunMigrationTransaction("create-conflict-archive", {plan.createConflicts}, [](const std::vector<ISQLQuery *> &) {
					InspectDatabaseSchema();
				});
			});
		});
	});
}

std::string JsonEscape(std::string_view value)
{
	std::string escaped;
	escaped.reserve(value.size());
	for (const unsigned char character : value)
	{
		switch (character)
		{
			case '\\': escaped += "\\\\"; break;
			case '"': escaped += "\\\""; break;
			case '\b': escaped += "\\b"; break;
			case '\f': escaped += "\\f"; break;
			case '\n': escaped += "\\n"; break;
			case '\r': escaped += "\\r"; break;
			case '\t': escaped += "\\t"; break;
			default:
				if (character >= 0x20)
					escaped.push_back(static_cast<char>(character));
				break;
		}
	}
	return escaped;
}

bool ValidRuntimeNonce(std::string_view nonce)
{
	if (nonce.size() != 32)
		return false;
	for (const unsigned char character : nonce)
	{
		if (!std::isxdigit(character))
			return false;
	}
	return true;
}

bool WriteRuntimeEvidence(const std::string &nonce, const std::string &columnType,
	bool legacyInterface, bool v2Interface)
{
	const std::string finalPath = "addons/data/vip-runtime-validation-" + nonce + ".json";
	const std::string temporaryPath = finalPath + ".tmp";
	std::string evidence =
		"{\n"
		"  \"schema\": \"https://github.com/bywinsty/cs2-vip/runtime-probe/v1\",\n"
		"  \"nonce\": \"" + nonce + "\",\n"
		"  \"build_commit\": \"" VIP_BUILD_COMMIT "\",\n"
		"  \"version\": \"" + JsonEscape(g_PLAPI->GetVersion()) + "\",\n"
		"  \"interfaces\": {\"IVIPApi001\": " + (legacyInterface ? std::string("true") : std::string("false")) +
		", \"IVIPApi002\": " + (v2Interface ? std::string("true") : std::string("false")) + "},\n"
		"  \"ready\": true,\n"
		"  \"migration\": {\"status\": \"ready\", \"account_id_type\": \"" + JsonEscape(columnType) + "\"}\n"
		"}\n";
	FileHandle_t output = g_pFullFileSystem->Open(temporaryPath.c_str(), "wb", "GAME");
	if (!output)
		return false;
	const int written = g_pFullFileSystem->Write(evidence.data(), static_cast<int>(evidence.size()), output);
	g_pFullFileSystem->Close(output);
	if (written != static_cast<int>(evidence.size()))
	{
		g_pFullFileSystem->RemoveFile(temporaryPath.c_str(), "GAME");
		return false;
	}
	if (!g_pFullFileSystem->RenameFile(temporaryPath.c_str(), finalPath.c_str(), "GAME"))
	{
		g_pFullFileSystem->RemoveFile(temporaryPath.c_str(), "GAME");
		return false;
	}
	return true;
}

void RuntimeProbeCommand(const CCommandContext &context, const CCommand &args)
{
	if (context.GetPlayerSlot().Get() >= 0)
	{
		META_CONPRINT("[VIP-CI] vip_runtime_probe is server-console-only\n");
		return;
	}
	if (args.ArgC() != 2 || !ValidRuntimeNonce(args[1]))
	{
		META_CONPRINT("[VIP-CI] Usage: vip_runtime_probe <32-hex-nonce>\n");
		return;
	}
	if (!DatabaseReady())
	{
		META_CONPRINT("[VIP-CI] Runtime probe rejected: database is not ready\n");
		return;
	}

	const std::string nonce(args[1]);
	g_pConnection->ExecuteTransaction(
		Transaction{std::vector<std::string>{
			"SELECT `COLUMN_TYPE` FROM `INFORMATION_SCHEMA`.`COLUMNS` "
			"WHERE `TABLE_SCHEMA` = DATABASE() AND `TABLE_NAME` = 'vip_users' "
			"AND `COLUMN_NAME` = 'account_id';"}},
		[nonce](std::vector<ISQLQuery *> results) {
			if (!DatabaseReady() || results.empty() || !results.front())
				return;
			ISQLResult *result = results.front()->GetResultSet();
			if (!result || !result->FetchRow())
				return;
			const char *rawColumnType = result->GetString(0);
			if (!rawColumnType)
				return;
			const std::string columnType = vip_database::LowerAscii(rawColumnType);
			if (columnType != "bigint unsigned")
			{
				META_CONPRINT("[VIP-CI] Runtime probe rejected: account_id is not BIGINT UNSIGNED\n");
				return;
			}
			int legacyResult = META_IFACE_FAILED;
			int v2Result = META_IFACE_FAILED;
			const bool legacy = g_SMAPI->MetaFactory(VIP_INTERFACE_LEGACY, &legacyResult, nullptr) != nullptr
				&& legacyResult != META_IFACE_FAILED;
			const bool v2 = g_SMAPI->MetaFactory(VIP_INTERFACE_V2, &v2Result, nullptr) != nullptr
				&& v2Result != META_IFACE_FAILED;
			if (!legacy || !v2 || !WriteRuntimeEvidence(nonce, columnType, legacy, v2))
				META_CONPRINT("[VIP-CI] Runtime probe evidence was not written\n");
			else
				META_CONPRINTF("[VIP-CI] Runtime probe evidence ready for nonce %s\n", nonce.c_str());
		},
		[](std::string error, int queryIndex) {
			META_CONPRINTF("[VIP-CI] Runtime probe SQL failed at query %d: %s\n", queryIndex, error.c_str());
		});
}

ConCommand g_RuntimeProbeCommand(
	"vip_runtime_probe",
	RuntimeProbeCommand,
	"Write nonce-bound VIP runtime validation evidence (server console only)",
	FCVAR_SERVER_CAN_EXECUTE
);

void VIPApi::VIP_PrintToCenter(int Slot, const char *msg, ...)
{
	va_list args;
	va_start(args, msg);

	char buf[256];
	V_vsnprintf(buf, sizeof(buf), msg, args);
	va_end(args);

	g_pUtils->PrintToCenter(Slot, buf);
}

std::map<std::string, std::string> GetGroupKV(int iSlot)
{
    CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
    if (!pController) return {};
    uint64 m_steamID = pController->m_steamID();
    if(m_steamID == 0) return {};

    auto vipGroup = g_VipPlayer.find(m_steamID);
    if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
        return {};
    
    if(g_pKVUser[iSlot].size() > 0)
        return g_pKVUser[iSlot];

    VipPlayer& player = vipGroup->second;
    if (player.TimeEnd <= std::time(0) && player.TimeEnd != 0)
        return {};

    std::map<std::string, std::string> vipPlayer = g_VipGroups[player.sGroup];
    if (vipPlayer.empty())
        return {};
    
    auto it = vipPlayer.find("legacy");
    if (it == vipPlayer.end() || it->second.empty())
        return vipPlayer;

    const char* vipGroupLegacy = it->second.c_str();
    while(vipGroupLegacy && vipGroupLegacy[0]) {
        auto vipLegacy = g_VipGroups[vipGroupLegacy];
        if(!vipLegacy.empty()) {
            vipGroupLegacy = vipLegacy["legacy"].c_str();
            for(auto& [key, value] : vipLegacy) if(vipPlayer[key].empty()) vipPlayer[key] = value;
        } else {
            break;
        }
    }
    g_pKVUser[iSlot] = vipPlayer;
    return vipPlayer;
}

const char *VIPApi::VIP_GetTranslate(const char* phrase)
{
    return g_vecPhrases[std::string(phrase)].c_str();
}

bool LoadVips()
{
	g_VipGroups.clear();
	for (int i = 0; i < 64; i++) g_pKVUser[i].clear();
	KeyValues* pKVVips = new KeyValues("VIP");
	
	if (!pKVVips->LoadFromFile(g_pFullFileSystem, "addons/configs/vip/groups.ini"))
	{
		g_pUtils->ErrorLog("[%s] Failed to load vip config 'addons/configs/vip/groups.ini'", g_PLAPI->GetLogTag());
		return false;
	}
	m_iServerID = pKVVips->GetInt("server_id");
	for (KeyValues* pKey = pKVVips->GetFirstSubKey(); pKey; pKey = pKey->GetNextKey())
	{
		const char* sGroup = pKey->GetName();
		std::map<std::string,std::string> group;
		FOR_EACH_VALUE(pKey, pValue)
		{
			group[pValue->GetName()] = pValue->GetString(nullptr, nullptr);
		}
		g_VipGroups[std::string(sGroup)] = group;
	}
	return true;
}

CON_COMMAND_F(vip_reload, "reloads list of vip groups", FCVAR_NONE)
{	
	if (LoadVips())
	{
		ConColorMsg({ 0, 255, 0, 255 }, "VIP groups has been successfully updated\n");
	}
}

CON_COMMAND_F(mm_reload_vip, "check player vip", FCVAR_NONE)
{
	if (!DatabaseReady())
	{
		META_CONPRINT("[VIP] Database is not ready\n");
		return;
	}
	if (args.ArgC() > 1 && args[1][0])
	{
		bool bFound = false;
		CCSPlayerController* pController;
		int iSlot = 0;
		uint64 iNumericTarget = 0;
		const bool bNumericTarget = ParseNumericArgument(args[1], iNumericTarget);
		for (int i = 0; i < 64; i++)
		{
			pController = CCSPlayerController::FromSlot(i);
			if (!pController)
				continue;
			uint64 m_steamID = pController->m_steamID();
			if(m_steamID == 0)
				continue;
			if(strstr(pController->m_iszPlayerName(), args[1]) || (bNumericTarget && (m_steamID == iNumericTarget || iNumericTarget == static_cast<uint64>(i) || iNumericTarget == engine->GetClientXUID(i))))
			{
				bFound = true;
				iSlot = i;
				break;
			}
		}
		if(bFound)
		{
			uint64 m_steamID = pController->m_steamID();
			auto vipGroup = g_VipPlayer.find(m_steamID);
			if (vipGroup != g_VipPlayer.end())
				g_VipPlayer.erase(vipGroup);
			g_pKVUser[iSlot].clear();
			char szQuery[256];
			g_SMAPI->Format(szQuery, sizeof(szQuery), "SELECT `group`, `expires` FROM `vip_users` WHERE `account_id` = %llu AND `sid` = %d;", static_cast<unsigned long long>(m_steamID), m_iServerID);
			g_pConnection->Query(szQuery, [iSlot, m_steamID, pController](ISQLQuery* test)
			{
				auto results = test->GetResultSet();
				if(results->FetchRow())
				{
					VipPlayer& player = g_VipPlayer[m_steamID];
					player.sGroup = results->GetString(0);
					player.TimeEnd = results->GetInt(1);
					char szQuery[256];
					g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, g_pVIPCore->VIP_IsClientVIP(iSlot));
					if(player.TimeEnd > std::time(0) || player.TimeEnd == 0)
					{
						if(g_pVIPCore->VIP_IsValidVIPGroup(player.sGroup.c_str()))
						{
							g_SMAPI->Format(szQuery, sizeof(szQuery), "UPDATE vip_users SET name = '%s', lastvisit = %i  WHERE account_id = '%llu' AND `sid` = %i;", g_pConnection->Escape(engine->GetClientConVarValue(iSlot, "name")).c_str(), std::time(0), static_cast<unsigned long long>(m_steamID), m_iServerID);
							if(player.TimeEnd == 0) 
								g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("WelcomePerm"), pController->m_iszPlayerName());
							else
							{
								time_t currentTime_t = static_cast<time_t>(player.TimeEnd);
								char buffer[80];
								std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&currentTime_t));
								g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("Welcome"), pController->m_iszPlayerName(), buffer);
							}
						}
					}
					else
						g_SMAPI->Format(szQuery, sizeof(szQuery), "DELETE FROM vip_users WHERE account_id = '%llu' AND `sid` = %i;", static_cast<unsigned long long>(m_steamID), m_iServerID);
					g_pConnection->Query(szQuery, [](ISQLQuery* test){});
				}
				else g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, false);
			});
		}
		else META_CONPRINT("[VIP] Player not found\n");
	}
	else META_CONPRINT("[VIP] Usage: mm_reload_vip <userid|nickname|accountid>\n");
}

CON_COMMAND_F(vip_remove, "remove player vip", FCVAR_NONE)
{	
	if (!DatabaseReady())
	{
		META_CONPRINT("[VIP] Database is not ready\n");
		return;
	}
	if (args.ArgC() > 1 && args[1][0])
	{
		bool bFound = false;
		int iSlot = 0; 
		uint64 iNumericTarget = 0;
		const bool bNumericTarget = ParseNumericArgument(args[1], iNumericTarget);
		for (int i = 0; i < 64; i++)
		{
			CCSPlayerController* pController = CCSPlayerController::FromSlot(i);
			if (!pController)
				continue;
			uint64 m_steamID = pController->m_steamID();
			if(m_steamID == 0)
				continue;
			if(strstr(pController->m_iszPlayerName(), args[1]) || (bNumericTarget && (m_steamID == iNumericTarget || iNumericTarget == static_cast<uint64>(i))))
			{
				bFound = true;
				iSlot = i;
				break;
			}
		}
		if(bFound)
		{
			if(!g_pVIPCore->VIP_IsClientVIP(iSlot))
				META_CONPRINT("[VIP] The player has no VIP status\n");
			else
			{
				g_pVIPCore->VIP_RemoveClientVIP(iSlot, 1);
				META_CONPRINT("[VIP] You have successfully removed the player's VIP status\n");
			}
		}
		else META_CONPRINT("[VIP] Player not found\n");
	}
	else META_CONPRINT("[VIP] Usage: vip_remove <userid|nickname|accountid>\n");
}

CON_COMMAND_F(vip_give, "give player vip", FCVAR_NONE)
{	
	if (!DatabaseReady())
	{
		META_CONPRINT("[VIP] Database is not ready\n");
		return;
	}
	if (args.ArgC() > 3 && args[1][0] && args[3][0])
	{
		uint64 durationSeconds = 0;
		if (!ParseNumericArgument(args[2], durationSeconds) || durationSeconds > static_cast<uint64>(std::numeric_limits<int>::max()))
		{
			META_CONPRINT("[VIP] Invalid duration\n");
			return;
		}
		bool bFound = false;
		int iSlot = 0;
		uint64 iNumericTarget = 0;
		const bool bNumericTarget = ParseNumericArgument(args[1], iNumericTarget);
		for (int i = 0; i < 64; i++)
		{
			CCSPlayerController* pController = CCSPlayerController::FromSlot(i);
			if (!pController)
				continue;
			uint64 m_steamID = pController->m_steamID();
			if(m_steamID == 0)
				continue;

			if(!pController->GetPlayerPawn() || !pController->m_hPawn())
				continue;
			if(strstr(pController->m_iszPlayerName(), args[1]) || (bNumericTarget && (m_steamID == iNumericTarget || iNumericTarget == static_cast<uint64>(i))))
			{
				bFound = true;
				iSlot = i;
				break;
			}
		}
		if(bFound)
		{
			if(g_pVIPCore->VIP_IsClientVIP(iSlot))
				META_CONPRINT("[VIP] The player already has VIP status\n");
			else
			{
				g_pVIPCore->VIP_GiveClientVIP(iSlot, static_cast<int>(durationSeconds), args[3], true);
				META_CONPRINT("[VIP] You have successfully granted VIP status\n");
			}
		}
		else if(std::strlen(args[1]) >= 9 && std::strlen(args[1]) <= 20)
		{
			uint64 accountID = 0;
			if (!vip_database::ParseAccountIdentifier(std::string_view(args[1]), accountID))
			{
				META_CONPRINT("[VIP] Invalid account ID\n");
				return;
			}
			accountID = vip_database::NormalizeSteamID64(accountID);
			char szQuery[256];
			g_SMAPI->Format(szQuery, sizeof(szQuery), "INSERT INTO `vip_users` (`account_id`, `name`, `lastvisit`, `sid`, `group`, `expires`) VALUES ('%llu', '%s', '%i', '%i', '%s', '%i');", static_cast<unsigned long long>(accountID), "none", std::time(0), m_iServerID, args[3], durationSeconds != 0 ? std::time(0) + static_cast<int>(durationSeconds) : 0);
			g_pConnection->Query(szQuery, [](ISQLQuery* test){});
			META_CONPRINT("[VIP] You have successfully granted VIP status\n");
		}
		else META_CONPRINT("[VIP] Player not found\n");
	}
	else META_CONPRINT("[VIP] Usage: vip_give <userid|nickname|accountid> <time_second> <group>\n");
}

const char* VIPApi::VIP_GetClientCookie(int iSlot, const char* sCookieName)
{
	if(g_pCookies) {
		char szCookie[256];
		g_SMAPI->Format(szCookie, sizeof(szCookie), "%s.%s", g_pVIPCore->VIP_GetClientVIPGroup(iSlot), sCookieName);
		return g_pCookies->GetCookie(iSlot, szCookie);
	} else {
		CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
		if (!pController) return "";
		uint64 m_steamID = pController->m_steamID();
		if(m_steamID == 0) return "";
		if (!g_hKVData) return "";
		MigrateLegacyClientData(m_steamID);
		KeyValues *hData = g_hKVData->FindKey(std::to_string(m_steamID).c_str(), false);
		if(!hData) return "";
		const char* sValue = hData->GetString(sCookieName);
		return sValue;
	}
}

bool VIPApi::VIP_SetClientCookie(int iSlot, const char* sCookieName, const char* sData)
{
	if(g_pCookies) {
		char szCookie[256];
		g_SMAPI->Format(szCookie, sizeof(szCookie), "%s.%s", g_pVIPCore->VIP_GetClientVIPGroup(iSlot), sCookieName);
		g_pCookies->SetCookie(iSlot, szCookie, sData);
		return true;
	} else {
		CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
		if (!pController) return false;
		uint64 m_steamID = pController->m_steamID();
		if(m_steamID == 0) return false;
		if (!g_hKVData) return false;
		MigrateLegacyClientData(m_steamID);

		KeyValues *hData = g_hKVData->FindKey(std::to_string(m_steamID).c_str(), true);
		hData->SetString(sCookieName, sData);
		g_hKVData->SaveToFile(g_pFullFileSystem, "addons/data/vip_data.ini");
		return true;
	}
	return false;
}

bool LoadVIPData()
{
	g_hKVData = new KeyValues("Data");

	const char *pszPath = "addons/data/vip_data.ini";

	if (!g_hKVData->LoadFromFile(g_pFullFileSystem, pszPath))
	{
		g_pUtils->ErrorLog("[%s] Failed to load vip config 'addons/data/vip_data.ini'", g_PLAPI->GetLogTag());
		return false;
	}

	return true;
}

void* VIP::OnMetamodQuery(const char* iface, int* ret)
{
	if (!strcmp(iface, VIP_INTERFACE_LEGACY))
	{
		*ret = META_IFACE_OK;
		return static_cast<IVIPApi001*>(g_pVIPCore);
	}
	if (!strcmp(iface, VIP_INTERFACE_V2))
	{
		*ret = META_IFACE_OK;
		return static_cast<IVIPApi002*>(g_pVIPCore);
	}

	*ret = META_IFACE_FAILED;
	return nullptr;
}

bool VIP::Load(PluginId id, ISmmAPI* ismm, char* error, size_t maxlen, bool late)
{
	PLUGIN_SAVEVARS();

	GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
	GET_V_IFACE_ANY(GetEngineFactory, g_pSchemaSystem, ISchemaSystem, SCHEMASYSTEM_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetFileSystemFactory, g_pFullFileSystem, IFileSystem, FILESYSTEM_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetEngineFactory, engine, IVEngineServer2, SOURCE2ENGINETOSERVER_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetServerFactory, g_pSource2Server, ISource2Server, SOURCE2SERVER_INTERFACE_VERSION);
	GET_V_IFACE_ANY(GetServerFactory, g_pSource2GameClients, IServerGameClients, SOURCE2GAMECLIENTS_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pNetworkServerService, INetworkServerService, NETWORKSERVERSERVICE_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pGameResourceServiceServer, IGameResourceService, GAMERESOURCESERVICESERVER_INTERFACE_VERSION);

	g_SMAPI->AddListener( this, this );

	SH_ADD_HOOK(IServerGameDLL, GameFrame, g_pSource2Server, SH_MEMBER(this, &VIP::GameFrame), true);
	SH_ADD_HOOK(IServerGameClients, ClientPutInServer, g_pSource2GameClients, SH_MEMBER(this, &VIP::OnClientPutInServer), true);
	SH_ADD_HOOK_MEMFUNC(IServerGameClients, ClientDisconnect, g_pSource2GameClients, this, &VIP::OnClientDisconnect, true);

	ConVar_Register(FCVAR_GAMEDLL);

	g_pVIPApi = new VIPApi();
	g_pVIPCore = g_pVIPApi;

	return true;
}

bool VIP::Unload(char *error, size_t maxlen)
{
	SH_REMOVE_HOOK(IServerGameDLL, GameFrame, g_pSource2Server, SH_MEMBER(this, &VIP::GameFrame), true);
    SH_REMOVE_HOOK(IServerGameClients, ClientPutInServer, g_pSource2GameClients, SH_MEMBER(this, &VIP::OnClientPutInServer), true);
	SH_REMOVE_HOOK_MEMFUNC(IServerGameClients, ClientDisconnect, g_pSource2GameClients, this, &VIP::OnClientDisconnect, true);

	ConVar_Unregister();

	if (g_pConnection)
	{
		g_pConnection->Destroy();
		g_pConnection = nullptr;
	}
	g_databaseState = DatabaseState::Disconnected;
	if (g_pVIPApi)
		g_pVIPApi->SetReady(false);
	
	return true;
}

void VIP::OnClientPutInServer(CPlayerSlot slot, char const* pszName, int type, uint64 xuid)
{
	if(xuid == 0) return;
	int iSlot = slot.Get();
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup != g_VipPlayer.end())
	{
		VipPlayer& player = vipGroup->second;
		if(g_pVIPCore->VIP_IsValidVIPGroup(player.sGroup.c_str()))
		{
			if(player.TimeEnd == 0) 
				g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("WelcomePerm"), engine->GetClientConVarValue(iSlot, "name"));
			else
			{
				time_t currentTime_t = static_cast<time_t>(player.TimeEnd);
				char buffer[80];
				std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&currentTime_t));
				g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("Welcome"), engine->GetClientConVarValue(iSlot, "name"), buffer);
			}
		}
	}
}

void OnStartupServer()
{
	g_pGameRules = nullptr;

	static bool bDone = false;
	if (!bDone)
	{
		g_pGameEntitySystem = GameEntitySystem();
		g_pEntitySystem = g_pUtils->GetCEntitySystem();
		bDone = true;
	}
	
	if(DatabaseReady())
	{
		char szQuery[256];
		g_SMAPI->Format(szQuery, sizeof(szQuery), "DELETE FROM `vip_users` WHERE `sid` = %i AND `expires` < %i AND `expires` <> 0;", m_iServerID, std::time(0));
		g_pConnection->Query(szQuery, [](ISQLQuery* test){});
	}
}

void VIP::GameFrame(bool simulating, bool bFirstTick, bool bLastTick)
{
	if (!g_pGameRules)
	{
		g_pGameRules = g_pUtils->GetCCSGameRules();
	}

	if(g_iLastTime == 0) g_iLastTime = std::time(0);
	else if(std::time(0) - g_iLastTime >= 1)
	{
		g_iLastTime = std::time(0);
		for (int i = 0; i < 64; i++)
		{
			if(g_pPlayers->IsFakeClient(i)) continue;
			if(!g_pPlayers->IsAuthenticated(i)) continue;
			if(!g_pPlayers->IsConnected(i)) continue;
			if(!g_pPlayers->IsInGame(i)) continue;
			if(!g_pPlayers->GetSteamID(i)) continue;
			uint64 m_steamID = g_pPlayers->GetSteamID64(i);
			if(m_steamID == 0) continue;
			auto vipGroup = g_VipPlayer.find(m_steamID);
			if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(i))
				continue;
			VipPlayer& player = vipGroup->second;
			if(player.TimeEnd < std::time(0) & player.TimeEnd != 0)
			{
				g_VipPlayer.erase(vipGroup);
				g_pKVUser[i].clear();
				g_pVIPApi->Call_VIP_OnVIPClientRemoved(i, 1);
				g_pUtils->PrintToChat(i, g_pVIPCore->VIP_GetTranslate("VIPExpired1"));
				g_pUtils->PrintToChat(i, g_pVIPCore->VIP_GetTranslate("VIPExpired2"));
				g_pUtils->PrintToChat(i, g_pVIPCore->VIP_GetTranslate("VIPExpired3"));
				
				if (DatabaseReady())
				{
					char szQuery[256];
					g_SMAPI->Format(szQuery, sizeof(szQuery), "DELETE FROM `vip_users` WHERE `account_id` = '%llu' AND `sid` = %i;", static_cast<unsigned long long>(m_steamID), m_iServerID);
					g_pConnection->Query(szQuery, [this](ISQLQuery* test){});
				}
			}
		}
	}
}

void OnPlayerSpawn(const char* szName, IGameEvent* event, bool bDontBroadcast)
{	
	CBasePlayerController* pPlayerController = static_cast<CBasePlayerController*>(event->GetPlayerController("userid"));
	if (!pPlayerController || pPlayerController->m_steamID() == 0) // Ignore bots
		return;

	g_pUtils->NextFrame([hPlayerController = CHandle<CBasePlayerController>(pPlayerController), pPlayerSlot = event->GetPlayerSlot("userid")]()
	{
		CCSPlayerController* pPlayerController = static_cast<CCSPlayerController*>(hPlayerController.Get());
		if (!pPlayerController)
			return;

		CCSPlayerPawnBase* pPlayerPawn = pPlayerController->m_hPlayerPawn();
		if (!pPlayerPawn || pPlayerPawn->m_lifeState() != LIFE_ALIVE)
			return;

		bool isVIP = g_pVIPCore->VIP_IsClientVIP(pPlayerPawn->m_hController()->m_pEntity->m_EHandle.GetEntryIndex() - 1);
		g_pVIPApi->Call_VIP_OnPlayerSpawn(pPlayerSlot.Get(), pPlayerPawn->m_iTeamNum(), isVIP);
	});
}

void OnRoundPreStart(const char* szName, IGameEvent* pEvent, bool bDontBroadcast)
{
	if (g_pGameRules)
	{
		g_bPistolRound = g_pGameRules->m_totalRoundsPlayed() == 0 || (g_pGameRules->m_bSwitchingTeamsAtRoundReset() && g_pGameRules->m_nOvertimePlaying() == 0) || g_pGameRules->m_bGameRestart();
	}
}

bool VIPApi::VIP_WarmupPeriod()
{
	return g_pGameRules->m_bWarmupPeriod();
}

bool VIPApi::VIP_PistolRound()
{
	return g_bPistolRound;
}

int VIPApi::VIP_GetClientAccessTime(int iSlot)
{
	if(g_pPlayers->IsFakeClient(iSlot)) return -1;
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return -1;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return -1;

	VipPlayer& player = vipGroup->second;
	if(player.TimeEnd <= std::time(0) && player.TimeEnd != 0) return -1;

	return player.TimeEnd;
}

bool VIPApi::VIP_SetClientAccessTime(int iSlot, int iTime, bool bInDB)
{
	if (bInDB && !DatabaseReady()) return false;
	if(g_pPlayers->IsFakeClient(iSlot)) return false;
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return false;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return false;

	VipPlayer& player = vipGroup->second;
	player.TimeEnd = iTime;

	if(bInDB)
	{
		char szQuery[256];
		g_SMAPI->Format(szQuery, sizeof(szQuery), "UPDATE `vip_users` SET `expires` = %i  WHERE `account_id` = '%llu' AND `sid` = %i;", iTime, static_cast<unsigned long long>(m_steamID), m_iServerID);
		g_pConnection->Query(szQuery, [this](ISQLQuery* test){});
	}
	return true;
}

bool VIPApi::VIP_GiveClientVIP(int iSlot, int iTime, const char* szGroup, bool bAddToDB)
{
	if (bAddToDB && !DatabaseReady()) return false;
	if(g_pPlayers->IsFakeClient(iSlot)) return false;
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return false;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup != g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot)) return false;

	VipPlayer& player = g_VipPlayer[m_steamID];
	player.sGroup = std::string(szGroup);
	player.TimeEnd = iTime != 0?std::time(0)+iTime:0;

	if(bAddToDB)
	{
		char szQuery[256];
		g_SMAPI->Format(szQuery, sizeof(szQuery), "INSERT INTO `vip_users` (`account_id`, `name`, `lastvisit`, `sid`, `group`, `expires`) VALUES ('%llu', '%s', '%i', '%i', '%s', '%i');", static_cast<unsigned long long>(m_steamID), g_pConnection->Escape(engine->GetClientConVarValue(iSlot, "name")).c_str(), std::time(0), m_iServerID, szGroup, iTime != 0?std::time(0)+iTime:0);
		g_pConnection->Query(szQuery, [this](ISQLQuery* test){});
	}
	if(player.TimeEnd == 0) g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("WelcomePerm"), engine->GetClientConVarValue(iSlot, "name"));
	else
	{
		time_t currentTime_t = (time_t)player.TimeEnd;
		char buffer[80];
    	std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&currentTime_t));
		g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("Welcome"), engine->GetClientConVarValue(iSlot, "name"), buffer);
	}
	g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, true);
	g_pVIPApi->Call_VIP_OnVIPClientAdded(iSlot);
	return true;
}

bool VIPApi::VIP_RemoveClientVIP(int iSlot, bool bNotify, bool bInDB)
{
	if (bInDB && !DatabaseReady()) return false;
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return false;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return false;

	g_VipPlayer.erase(vipGroup);
	g_pKVUser[iSlot].clear();
	if(bInDB)
	{
		char szQuery[256];
		g_SMAPI->Format(szQuery, sizeof(szQuery), "DELETE FROM `vip_users` WHERE `account_id` = '%llu' AND `sid` = %i;", static_cast<unsigned long long>(m_steamID), m_iServerID);
		g_pConnection->Query(szQuery, [this](ISQLQuery* test){});
	}
	if(bNotify)
	{
		g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("VIPExpired1"));
		g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("VIPExpired2"));
		g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("VIPExpired3"));
	}
	g_pVIPApi->Call_VIP_OnVIPClientRemoved(iSlot, 2);
	g_pVIPApi->Call_VIP_OnClientDisconnect(iSlot, false);
	return true;
}

bool VIPApi::VIP_SetClientVIPGroup(int iSlot, const char* szGroup, bool bInDB)
{
	if (bInDB && !DatabaseReady()) return false;
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return false;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return false;
	
	VipPlayer& player = vipGroup->second;

	if(player.TimeEnd <= std::time(0) && player.TimeEnd != 0)
		return false;

	if(g_VipGroups[std::string(szGroup)].empty())
		return false;

	player.sGroup = std::string(szGroup);

	if(bInDB)
	{
		char szQuery[256];
		g_SMAPI->Format(szQuery, sizeof(szQuery), "UPDATE `vip_users` SET `group` = '%s'  WHERE `account_id` = '%llu' AND `sid` = %i;", szGroup, static_cast<unsigned long long>(m_steamID), m_iServerID);
		g_pConnection->Query(szQuery, [this](ISQLQuery* test){});
	}
	return true;
}

bool VIPApi::VIP_IsClientVIP(int iSlot)
{
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return false;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return false;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return false;

	VipPlayer& player = vipGroup->second;
	if(player.TimeEnd <= std::time(0) && player.TimeEnd != 0) return false;

	auto vipPlayer = g_VipGroups[player.sGroup];
	if (vipPlayer.empty())
		return false;
	return true;
}

int VIPApi::VIP_GetClientFeatureInt(int iSlot, const char* szFeature)
{
	std::map<std::string,std::string> Group = GetGroupKV(iSlot);
	if (Group.empty())
		return -1;
	const char* sCookie = VIP_GetClientCookie(iSlot, szFeature);
	if(strlen(sCookie) == 0 || atoi(sCookie) != 0)
		return Group[szFeature] != ""?atoi(Group[szFeature].c_str()):-1;
	return -1;
}

bool VIPApi::VIP_GetClientFeatureBool(int iSlot, const char* szFeature)
{
	std::map<std::string,std::string> Group = GetGroupKV(iSlot);
	if (Group.empty())
		return false;
	const char* sCookie = VIP_GetClientCookie(iSlot, szFeature);
	if(strlen(sCookie) == 0 || atoi(sCookie) != 0)
		return Group[szFeature] != ""?atoi(Group[szFeature].c_str()):false;
	return false;
}

float VIPApi::VIP_GetClientFeatureFloat(int iSlot, const char* szFeature)
{
	std::map<std::string,std::string> Group = GetGroupKV(iSlot);
	if (Group.empty())
		return 1.f;
	const char* sCookie = VIP_GetClientCookie(iSlot, szFeature);
	if(strlen(sCookie) == 0 || atoi(sCookie) != 0)
		return Group[szFeature] != ""?atof(Group[szFeature].c_str()):1.f;
	return 1.f;
}

const char* VIPApi::VIP_GetClientFeatureString(int iSlot, const char* szFeature)
{
	std::map<std::string,std::string> Group = GetGroupKV(iSlot);
	if (Group.empty())
		return "";
	const char* sCookie = VIP_GetClientCookie(iSlot, szFeature);
	if(strlen(sCookie) == 0 || atoi(sCookie) != 0)
		return Group[szFeature].c_str();
	return "";
}

const char* VIPApi::VIP_GetClientVIPGroup(int iSlot)
{
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return "";
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return "";

	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup == g_VipPlayer.end() || !engine->IsClientFullyAuthenticated(iSlot))
		return "";
	
	return vipGroup->second.sGroup.c_str();
}

CGameEntitySystem* VIPApi::VIP_GetEntitySystem()
{
	return g_pGameEntitySystem;
}

int VIPApi::VIP_GetTotalRounds()
{
	return g_pGameRules->m_totalRoundsPlayed();
}

void VIPApi::VIP_RegisterFeature(const char* szFeature, VIP_ValueType eValType, VIP_FeatureType eType, ItemSelectableCallback Item_select_callback, ItemTogglableCallback Item_togglable_callback, ItemDisplayCallback Item_display_callback)
{
	VIPFunctions& vip_func = g_VipFunctions[std::string(szFeature)];
	vip_func.eValType = eValType;
	vip_func.eType = eType;
	vip_func.Select_callback = Item_select_callback;
	vip_func.Togglable_callback = Item_togglable_callback;
	vip_func.Display_callback = Item_display_callback;
}

bool VIPApi::VIP_IsValidVIPGroup(const char* szGroup)
{
	return g_VipGroups[szGroup].empty()?false:true;
}

void LoadAuthorizedClient(int iSlot, uint64 iSteamID64)
{
	CCSPlayerController* pController = CCSPlayerController::FromSlot(iSlot);
	if (!pController) return;
	uint64 m_steamID = pController->m_steamID();
	if(m_steamID == 0) return;
	if (iSteamID64 != 0 && iSteamID64 != m_steamID) return;
	auto vipGroup = g_VipPlayer.find(m_steamID);
	if (vipGroup != g_VipPlayer.end())
		g_VipPlayer.erase(vipGroup);
	g_pKVUser[iSlot].clear();
	char szQuery[256];
	uint32 legacySteamID = static_cast<uint32>(m_steamID);
	g_SMAPI->Format(szQuery, sizeof(szQuery), "SELECT `group`, `expires` FROM `vip_users` WHERE `account_id` IN (%llu, %u) AND `sid` = %d ORDER BY `account_id` = %llu DESC LIMIT 1;", static_cast<unsigned long long>(m_steamID), legacySteamID, m_iServerID, static_cast<unsigned long long>(m_steamID));
	g_pConnection->Query(szQuery, [iSlot, m_steamID, legacySteamID](ISQLQuery* test)
	{
		CCSPlayerController* currentController = CCSPlayerController::FromSlot(iSlot);
		if (!currentController || currentController->m_steamID() != m_steamID)
			return;
		if (!DatabaseReady())
		{
			g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, false);
			return;
		}
		auto results = test->GetResultSet();
		if(results->FetchRow())
		{
			VipPlayer& player = g_VipPlayer[m_steamID];
			player.sGroup = results->GetString(0);
			player.TimeEnd = results->GetInt(1);
			char szQuery[256];
			g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, g_pVIPCore->VIP_IsClientVIP(iSlot));
			if(player.TimeEnd <= std::time(0) && player.TimeEnd != 0)
				g_SMAPI->Format(szQuery, sizeof(szQuery), "DELETE FROM vip_users WHERE account_id IN ('%llu', '%u') AND `sid` = %i;", static_cast<unsigned long long>(m_steamID), legacySteamID, m_iServerID);
			else
				g_SMAPI->Format(szQuery, sizeof(szQuery), "UPDATE vip_users SET account_id = '%llu', name = '%s', lastvisit = %i WHERE account_id IN ('%llu', '%u') AND `sid` = %i;", static_cast<unsigned long long>(m_steamID), g_pConnection->Escape(engine->GetClientConVarValue(iSlot, "name")).c_str(), std::time(0), static_cast<unsigned long long>(m_steamID), legacySteamID, m_iServerID);
			g_pConnection->Query(szQuery, [](ISQLQuery* test){});
		}
		else g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, false);
	});
}

void OnClientAuthorized(int iSlot, uint64 iSteamID64)
{
	if (!DatabaseReady())
	{
		if (g_databaseState == DatabaseState::Failed)
			g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, false);
		else
			g_pendingClientAuthorizations.emplace(iSlot, iSteamID64);
		return;
	}
	LoadAuthorizedClient(iSlot, iSteamID64);
}

void VIP::OnClientDisconnect( CPlayerSlot slot, ENetworkDisconnectionReason reason, const char *pszName, uint64 xuid, const char *pszNetworkID )
{
	for (auto pending = g_pendingClientAuthorizations.begin(); pending != g_pendingClientAuthorizations.end(); )
	{
		if (pending->first == slot.Get())
			pending = g_pendingClientAuthorizations.erase(pending);
		else
			++pending;
	}
	if (xuid == 0)
    	return;

	g_pVIPApi->Call_VIP_OnClientDisconnect(slot.Get(), g_pVIPCore->VIP_IsClientVIP(slot.Get()));
}

void ShowVIPMenu(int iSlot, bool bReopen);

void VIPApi::VIP_OpenMenu(int iSlot) {
	ShowVIPMenu(iSlot, true);
}

void VIPCallback(const char* szBack, const char* szFront, int iItem, int iSlot)
{
	if(iItem < 7)
	{
		const char* sCookie = g_pVIPCore->VIP_GetClientCookie(iSlot, szBack);
		VIPFunctions& vip_func = g_VipFunctions[std::string(szBack)];
		if(vip_func.eType != SELECTABLE)
		{
			int oldStatusValue;
			int newStatusValue;
			if(strlen(sCookie) == 0 || atoi(sCookie) != 0)
			{
				oldStatusValue = 1;
				newStatusValue = 0;
			}
			else
			{
				oldStatusValue = 0;
				newStatusValue = 1;
			}
			VIP_ToggleState oldStatus = static_cast<VIP_ToggleState>(oldStatusValue);
			VIP_ToggleState newStatus = static_cast<VIP_ToggleState>(newStatusValue);
			bool bBlock = false;
			if(vip_func.Togglable_callback) bBlock = vip_func.Togglable_callback(iSlot, szBack, oldStatus, newStatus);
			char szStatus[16];
			g_SMAPI->Format(szStatus, sizeof(szStatus), "%i", bBlock?oldStatusValue:newStatus);
			g_pVIPCore->VIP_SetClientCookie(iSlot, szBack, szStatus);
			ShowVIPMenu(iSlot, false);
		}
		else
		{
			bool bClose = false;
			if(vip_func.Select_callback) bClose = vip_func.Select_callback(iSlot, szBack);
			if(bClose)
			{
				g_pUtils->NextFrame([iSlot](){
					g_pMenus->ClosePlayerMenu(iSlot);
				});
			}
		}
	}
}

void ShowVIPMenu(int iSlot, bool bReopen)
{
	if(g_pPlayers->IsFakeClient(iSlot)) return;
	
	std::map<std::string,std::string> Group = GetGroupKV(iSlot);
	if (Group.empty()) {
		g_pUtils->PrintToChat(iSlot, g_pVIPCore->VIP_GetTranslate("NotAccess"));
		return;
	}

	Menu hMenu;
	g_pMenus->SetTitleMenu(hMenu, g_pVIPCore->VIP_GetTranslate("MenuTitle"));
	
	char sBuff[128];
	for (auto& [key, value] : Group) {
		const char *pszParam = key.c_str();
		if(!strcmp(pszParam, "legacy")) continue;
		const char *pszValue = value.c_str();
		const char *szTrans = g_pVIPCore->VIP_GetTranslate(pszParam);
		const char *szValue = g_pVIPCore->VIP_GetClientFeatureString(iSlot, pszParam); 
		VIPFunctions& vip_func = g_VipFunctions[std::string(pszParam)];
		if(vip_func.eValType != VIP_NULL && vip_func.eType != HIDE)
		{
			if(vip_func.eType == SELECTABLE)
				g_SMAPI->Format(sBuff, sizeof(sBuff), "%s", strlen(szTrans)?szTrans:pszParam);
			else
				g_SMAPI->Format(sBuff, sizeof(sBuff), "%s [%s]", strlen(szTrans)?szTrans:pszParam, strlen(szValue)?vip_func.eValType == VIP_BOOL?g_pVIPCore->VIP_GetTranslate("On"):szValue:g_pVIPCore->VIP_GetTranslate("Off"));
			std::string szDisplay;
			if(vip_func.Display_callback)
				szDisplay = vip_func.Display_callback(iSlot, pszParam);
			g_pMenus->AddItemMenu(hMenu, pszParam, size(szDisplay)?szDisplay.c_str():sBuff);
		}
	}

	g_pMenus->SetBackMenu(hMenu, false);
	g_pMenus->SetExitMenu(hMenu, true);
	g_pMenus->SetCallback(hMenu, VIPCallback);
	g_pMenus->DisplayPlayerMenu(hMenu, iSlot, true, bReopen);
}

bool OnVIPCommand(int iSlot, const char* szContent)
{
	ShowVIPMenu(iSlot, true);
	return false;
}

void OnClientCookiesLoaded(int iSlot)
{
	if (!DatabaseReady())
		return;
	g_pVIPApi->Call_VIP_OnClientLoaded(iSlot, g_pVIPCore->VIP_IsClientVIP(iSlot));
}

void VIP::AllPluginsLoaded()
{
	char error[64] = { 0 };
	int ret;
	g_pUtils = (IUtilsApi *)g_SMAPI->MetaFactory(Utils_INTERFACE, &ret, NULL);
	if (ret == META_IFACE_FAILED)
	{
		V_strncpy(error, "Missing Utils system plugin", 64);
		ConColorMsg(Color(255, 0, 0, 255), "[%s] %s\n", GetLogTag(), error);
		std::string sBuffer = "meta unload "+std::to_string(g_PLID);
		engine->ServerCommand(sBuffer.c_str());
		return;
	}

	g_pMenus = (IMenusApi *)g_SMAPI->MetaFactory(Menus_INTERFACE, &ret, NULL);
	if (ret == META_IFACE_FAILED)
	{
		g_pUtils->ErrorLog("[%s] Missing Menus system plugin", g_PLAPI->GetLogTag());
		ConColorMsg(Color(255, 0, 0, 255), "[%s] %s\n", GetLogTag(), error);
		std::string sBuffer = "meta unload "+std::to_string(g_PLID);
		engine->ServerCommand(sBuffer.c_str());
		return;
	}
	
	g_pPlayers = (IPlayersApi *)g_SMAPI->MetaFactory(PLAYERS_INTERFACE, &ret, NULL);
	if (ret == META_IFACE_FAILED)
	{
		g_pUtils->ErrorLog("[%s] Missing Players system plugin", g_PLAPI->GetLogTag());
		std::string sBuffer = "meta unload "+std::to_string(g_PLID);
		engine->ServerCommand(sBuffer.c_str());
		return;
	}

	g_pCookies = (ICookiesApi *)g_SMAPI->MetaFactory(COOKIES_INTERFACE, &ret, NULL);
	if (ret == META_IFACE_FAILED)
		g_pCookies = nullptr;
	else {
		g_pCookies->HookClientCookieLoaded(g_PLID, OnClientCookiesLoaded);
	}

	ISQLInterface* g_SqlInterface = (ISQLInterface *)g_SMAPI->MetaFactory(SQLMM_INTERFACE, &ret, nullptr);
	if (ret == META_IFACE_FAILED) {
		g_pUtils->ErrorLog("[%s] Missing MYSQL plugin", g_PLAPI->GetLogTag());
		std::string sBuffer = "meta unload "+std::to_string(g_PLID);
		engine->ServerCommand(sBuffer.c_str());
		return;
	}
	g_pMysqlClient = g_SqlInterface->GetMySQLClient();
	EmitRuntimeInterfaceProbe();
	
	g_pPlayers->HookOnClientAuthorized(g_PLID, OnClientAuthorized);

	{
		KeyValues* g_kvPhrases = new KeyValues("Phrases");
		const char *pszPath = "addons/translations/vip.phrases.txt";

		if (!g_kvPhrases->LoadFromFile(g_pFullFileSystem, pszPath))
		{
			g_pUtils->ErrorLog("[%s] Failed to load %s", g_PLAPI->GetLogTag(), pszPath);
			return;
		}

		const char* g_pszLanguage = g_pUtils->GetLanguage();
		for (KeyValues *pKey = g_kvPhrases->GetFirstTrueSubKey(); pKey; pKey = pKey->GetNextTrueSubKey())
			g_vecPhrases[std::string(pKey->GetName())] = std::string(pKey->GetString(g_pszLanguage));
	}

	KeyValues* pKVConfig = new KeyValues("Databases");

	if (!pKVConfig->LoadFromFile(g_pFullFileSystem, "addons/configs/databases.cfg")) {
		g_pUtils->ErrorLog("[%s] Failed to load databases config 'addons/config/databases.cfg'", g_PLAPI->GetLogTag());
		ConColorMsg(Color(255, 0, 0, 255), "[VIP] %s\n", error);
		FailDatabase("config", "databases.cfg could not be loaded");
		return;
	}

	pKVConfig = pKVConfig->FindKey("vip", false);
	if (!pKVConfig) {
		g_pUtils->ErrorLog("[%s] No databases.cfg 'vip'", g_PLAPI->GetLogTag());
		FailDatabase("config", "databases.cfg has no vip section");
		return;
	}

	MySQLConnectionInfo info;
	info.host = pKVConfig->GetString("host", nullptr);
	info.user = pKVConfig->GetString("user", nullptr);
	info.pass = pKVConfig->GetString("pass", nullptr);
	info.database = pKVConfig->GetString("database", nullptr);
	info.port = pKVConfig->GetInt("port");
	g_databaseState = DatabaseState::Connecting;
	if (!g_pMysqlClient)
	{
		FailDatabase("connect", "SQLMM did not provide a MySQL client");
		return;
	}
	g_pConnection = g_pMysqlClient->CreateMySQLConnection(info);
	if (!g_pConnection)
	{
		FailDatabase("connect", "SQLMM could not create a database connection");
		return;
	}

	g_pConnection->Connect([this](bool connect) {
		if (!connect) {
			FailDatabase("connect", "SQLMM could not connect to the configured database");
			return;
		}
		StartDatabaseMigration();
	});
	g_pUtils->RegCommand(g_PLID, {"mm_vip", "sm_vip"}, {"!vip"}, OnVIPCommand);
	g_pUtils->HookEvent(g_PLID, "player_spawn", OnPlayerSpawn);
	g_pUtils->HookEvent(g_PLID, "round_prestart", OnRoundPreStart);
	g_pUtils->StartupServer(g_PLID, OnStartupServer);
	LoadVips();
	LoadVIPData();
}

///////////////////////////////////////
const char* VIP::GetLicense()
{
	return "GPL";
}

const char* VIP::GetVersion()
{
	return "1.2.3.1";
}

const char* VIP::GetDate()
{
	return VIP_BUILD_DATE;
}

const char *VIP::GetLogTag()
{
	return "VIP";
}

const char* VIP::GetAuthor()
{
	return "Pisex";
}

const char* VIP::GetDescription()
{
	return "[VIP] Core";
}

const char* VIP::GetName()
{
	return "[VIP] Core";
}

const char* VIP::GetURL()
{
	return "https://discord.gg/g798xERK5Y";
}
