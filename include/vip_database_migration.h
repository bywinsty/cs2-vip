#pragma once

#include <charconv>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace vip_database
{

constexpr std::uint64_t kSteamID64Base = 76561197960265728ULL;
constexpr std::uint64_t kLegacyAccountMax = 0xFFFFFFFFULL;
constexpr const char *kMigrationVersion = "steamid64-v2";
constexpr const char *kMigrationChecksum = "6799cc4b228acdff3d599a31fb9546e4cd2641c82ff6169ae0728dcc2f457167";
constexpr const char *kMigrationLockPrefix = "cs2-vip:";

enum class AccountColumnKind
{
	SignedInt,
	UnsignedInt,
	SignedBigInt,
	UnsignedBigInt,
	Unknown,
};

inline bool ParseUnsignedDecimal(std::string_view value, std::uint64_t &result)
{
	if (value.empty())
		return false;

	const char *begin = value.data();
	const char *end = begin + value.size();
	std::uint64_t parsed = 0;
	const auto conversion = std::from_chars(begin, end, parsed, 10);
	if (conversion.ec != std::errc{} || conversion.ptr != end)
		return false;

	result = parsed;
	return true;
}

inline bool ParseAccountIdentifier(std::string_view value, std::uint64_t &result)
{
	return ParseUnsignedDecimal(value, result) && result != 0;
}

inline std::uint64_t NormalizeSteamID64(std::uint64_t accountId)
{
	if (accountId > 0 && accountId <= kLegacyAccountMax)
		return kSteamID64Base + accountId;
	return accountId;
}

inline std::string LowerAscii(std::string_view value)
{
	std::string result(value);
	for (char &character : result)
	{
		if (character >= 'A' && character <= 'Z')
			character = static_cast<char>(character - 'A' + 'a');
	}
	return result;
}

inline AccountColumnKind ClassifyAccountColumn(std::string_view dataType, std::string_view columnType)
{
	const std::string type = LowerAscii(columnType);
	const std::string data = LowerAscii(dataType);
	if (data == "int" || type.find("int(") == 0)
		return type.find("unsigned") != std::string::npos ? AccountColumnKind::UnsignedInt : AccountColumnKind::SignedInt;
	if (data == "bigint" || type.find("bigint") == 0)
		return type.find("unsigned") != std::string::npos ? AccountColumnKind::UnsignedBigInt : AccountColumnKind::SignedBigInt;
	return AccountColumnKind::Unknown;
}

inline bool IsSigned(AccountColumnKind kind)
{
	return kind == AccountColumnKind::SignedInt || kind == AccountColumnKind::SignedBigInt;
}

inline bool IsLegacyWidth(AccountColumnKind kind)
{
	return kind == AccountColumnKind::SignedInt || kind == AccountColumnKind::UnsignedInt;
}

struct MigrationPlan
{
	struct Step
	{
		std::string name;
		std::string sql;
		bool isDDL;
		bool idempotent;
	};

	std::string lockQuery;
	std::string createUsers;
	std::string createHistory;
	std::string createConflicts;
	std::string widenSignedColumn;
	std::vector<std::string> archiveConflicts;
	std::vector<std::string> removeConflicts;
	std::string normalizeLegacy;
	std::string verifyLegacy;
	std::string warnUnmapped;
	std::string finalizeUnsignedColumn;
	std::string recordVersion;
	std::string releaseLockQuery;
	std::string verifyVersion;
	std::vector<Step> steps;
};

inline MigrationPlan BuildMigrationPlan()
{
	MigrationPlan plan;
	const std::string lockExpression = "CONCAT('" + std::string(kMigrationLockPrefix) + "', LEFT(SHA2(CONCAT('lock:', DATABASE()), 256), 32))";
	plan.lockQuery = "SELECT GET_LOCK(" + lockExpression + ", 30);";
	plan.releaseLockQuery = "SELECT RELEASE_LOCK(" + lockExpression + ");";
	plan.createUsers =
		"CREATE TABLE IF NOT EXISTS `vip_users` ("
		"`account_id` BIGINT UNSIGNED NOT NULL, "
		"`name` VARCHAR(64) NOT NULL DEFAULT 'unknown' COLLATE 'utf8mb4_unicode_ci', "
		"`lastvisit` INT UNSIGNED NOT NULL DEFAULT 0, "
		"`sid` INT UNSIGNED NOT NULL, "
		"`group` VARCHAR(64) NOT NULL, "
		"`expires` INT UNSIGNED NOT NULL DEFAULT 0, "
		"CONSTRAINT pk_PlayerID PRIMARY KEY (`account_id`, `sid`)"
		") DEFAULT CHARSET=utf8mb4;";
	plan.createHistory =
		"CREATE TABLE IF NOT EXISTS `vip_schema_migrations` ("
		"`version` VARCHAR(64) NOT NULL, `checksum` CHAR(64) NOT NULL, "
		"`applied_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
		"PRIMARY KEY (`version`)"
		") DEFAULT CHARSET=utf8mb4;";
	plan.createConflicts =
		"CREATE TABLE IF NOT EXISTS `vip_users_migration_conflicts` ("
		"`migration_version` VARCHAR(64) NOT NULL, "
		"`original_account_id` BIGINT NOT NULL, `canonical_account_id` BIGINT UNSIGNED NOT NULL, "
		"`sid` INT UNSIGNED NOT NULL, `name` VARCHAR(64) NOT NULL, "
		"`lastvisit` INT UNSIGNED NOT NULL, `group` VARCHAR(64) NOT NULL, "
		"`expires` INT UNSIGNED NOT NULL, `reason` VARCHAR(64) NOT NULL, "
		"`archived_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
		"PRIMARY KEY (`migration_version`, `original_account_id`, `canonical_account_id`, `sid`, `reason`)"
		") DEFAULT CHARSET=utf8mb4;";
	plan.widenSignedColumn =
		"ALTER TABLE `vip_users` MODIFY `account_id` BIGINT SIGNED NOT NULL;";
	const std::string legacyExpression =
		"(" + std::string("CASE WHEN legacy.`account_id` < 0 THEN legacy.`account_id` + 4294967296 "
		"ELSE legacy.`account_id` END") + ")";
	plan.archiveConflicts = {
		"INSERT IGNORE INTO `vip_users_migration_conflicts` "
		"(`migration_version`,`original_account_id`,`canonical_account_id`,`sid`,`name`,`lastvisit`,`group`,`expires`,`reason`) "
		"SELECT '" + std::string(kMigrationVersion) + "', legacy.`account_id`, canonical.`account_id`, legacy.`sid`, "
		"legacy.`name`, legacy.`lastvisit`, legacy.`group`, legacy.`expires`, 'canonical-steamid64-wins' "
		"FROM `vip_users` legacy JOIN `vip_users` canonical "
		"ON canonical.`sid` = legacy.`sid` AND canonical.`account_id` = 76561197960265728 + " + legacyExpression + " "
		"WHERE (legacy.`account_id` < 0 OR legacy.`account_id` BETWEEN 1 AND 4294967295);",
		"INSERT IGNORE INTO `vip_users_migration_conflicts` "
		"(`migration_version`,`original_account_id`,`canonical_account_id`,`sid`,`name`,`lastvisit`,`group`,`expires`,`reason`) "
		"SELECT '" + std::string(kMigrationVersion) + "', negative.`account_id`, positive.`account_id`, negative.`sid`, "
		"negative.`name`, negative.`lastvisit`, negative.`group`, negative.`expires`, 'positive-legacy-wins' "
		"FROM `vip_users` negative JOIN `vip_users` positive "
		"ON positive.`sid` = negative.`sid` AND positive.`account_id` = negative.`account_id` + 4294967296 "
		"WHERE negative.`account_id` < 0;",
	};
	plan.removeConflicts = {
		"DELETE legacy FROM `vip_users` legacy JOIN `vip_users` canonical "
		"ON canonical.`sid` = legacy.`sid` AND canonical.`account_id` = 76561197960265728 + " + legacyExpression + " "
		"WHERE (legacy.`account_id` < 0 OR legacy.`account_id` BETWEEN 1 AND 4294967295);",
		"DELETE negative FROM `vip_users` negative JOIN `vip_users` positive "
		"ON positive.`sid` = negative.`sid` AND positive.`account_id` = negative.`account_id` + 4294967296 "
		"WHERE negative.`account_id` < 0;",
	};
	plan.normalizeLegacy =
		"UPDATE `vip_users` SET `account_id` = 76561197960265728 + "
		"CASE WHEN `account_id` < 0 THEN `account_id` + 4294967296 ELSE `account_id` END "
		"WHERE `account_id` < 0 OR `account_id` BETWEEN 1 AND 4294967295;";
	plan.verifyLegacy =
		"SELECT COUNT(*) FROM `vip_users` WHERE `account_id` < 0 OR `account_id` BETWEEN 1 AND 4294967295;";
	plan.warnUnmapped =
		"SELECT COUNT(*) FROM `vip_users` WHERE `account_id` = 0 OR "
		"(`account_id` > 4294967295 AND `account_id` < 76561197960265729) OR "
		"`account_id` > 76561202255233023;";
	plan.finalizeUnsignedColumn =
		"ALTER TABLE `vip_users` MODIFY `account_id` BIGINT UNSIGNED NOT NULL;";
	plan.recordVersion =
		"INSERT IGNORE INTO `vip_schema_migrations` (`version`,`checksum`) VALUES ('" + std::string(kMigrationVersion) + "', "
		"'" + std::string(kMigrationChecksum) + "');";
	plan.verifyVersion =
		"SELECT COUNT(*) FROM `vip_schema_migrations` WHERE `version`='" + std::string(kMigrationVersion) + "' AND `checksum`='"
		+ std::string(kMigrationChecksum) + "';";
	plan.steps = {
		{"acquire-lock", plan.lockQuery, false, false},
		{"create-users-table", plan.createUsers, true, true},
		{"create-migration-history", plan.createHistory, true, true},
		{"create-conflict-archive", plan.createConflicts, true, true},
		{"widen-signed-column", plan.widenSignedColumn, true, true},
		{"archive-canonical-conflicts", plan.archiveConflicts[0], false, true},
		{"archive-legacy-conflicts", plan.archiveConflicts[1], false, true},
		{"remove-canonical-conflicts", plan.removeConflicts[0], false, true},
		{"remove-legacy-conflicts", plan.removeConflicts[1], false, true},
		{"normalize-legacy", plan.normalizeLegacy, false, true},
		{"verify-legacy", plan.verifyLegacy, false, true},
		{"warn-unmapped", plan.warnUnmapped, false, true},
		{"finalize-unsigned-column", plan.finalizeUnsignedColumn, true, true},
		{"record-version", plan.recordVersion, false, true},
		{"verify-version", plan.verifyVersion, false, true},
		{"release-lock", plan.releaseLockQuery, false, false},
	};
	return plan;
}

} // namespace vip_database
