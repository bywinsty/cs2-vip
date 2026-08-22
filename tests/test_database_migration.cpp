#include <cassert>
#include <cstdint>
#include <string>

#include "vip_database_migration.h"

int main()
{
    using namespace vip_database;

    std::uint64_t value = 0;
    assert(ParseUnsignedDecimal("0", value) && value == 0);
    assert(ParseUnsignedDecimal("4294967295", value) && value == 4294967295ULL);
    assert(ParseUnsignedDecimal("18446744073709551615", value));
    assert(!ParseUnsignedDecimal("", value));
    assert(!ParseUnsignedDecimal("+1", value));
    assert(!ParseUnsignedDecimal(" 1", value));
    assert(!ParseUnsignedDecimal("1 ", value));
    assert(!ParseUnsignedDecimal("1x", value));
    assert(!ParseUnsignedDecimal("18446744073709551616", value));
    assert(!ParseAccountIdentifier("0", value));
    assert(ParseAccountIdentifier("1", value) && NormalizeSteamID64(value) == kSteamID64Base + 1);
    assert(NormalizeSteamID64(76561197960287930ULL) == 76561197960287930ULL);

    assert(ClassifyAccountColumn("int", "int(11)") == AccountColumnKind::SignedInt);
    assert(ClassifyAccountColumn("int", "int(10) unsigned") == AccountColumnKind::UnsignedInt);
    assert(ClassifyAccountColumn("bigint", "bigint(20)") == AccountColumnKind::SignedBigInt);
    assert(ClassifyAccountColumn("bigint", "bigint(20) unsigned") == AccountColumnKind::UnsignedBigInt);
    assert(ClassifyAccountColumn("varchar", "varchar(32)") == AccountColumnKind::Unknown);

    const MigrationPlan plan = BuildMigrationPlan();
    assert(plan.lockQuery.find("GET_LOCK") != std::string::npos);
    assert(plan.createHistory.find("vip_schema_migrations") != std::string::npos);
    assert(plan.createConflicts.find("vip_users_migration_conflicts") != std::string::npos);
    assert(plan.archiveConflicts.size() == 2);
    assert(plan.removeConflicts.size() == 2);
    assert(plan.normalizeLegacy.find("4294967296") != std::string::npos);
    assert(plan.warnUnmapped.find("account_id = 0") != std::string::npos);
    assert(plan.finalizeUnsignedColumn.find("BIGINT UNSIGNED") != std::string::npos);
    assert(plan.recordVersion.find("steamid64-v2") != std::string::npos);
    return 0;
}
