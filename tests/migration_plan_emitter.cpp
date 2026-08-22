#include <iostream>
#include <string>

#include "vip_database_migration.h"

namespace
{
std::string JsonEscape(const std::string &value)
{
	std::string result;
	for (const unsigned char character : value)
	{
		switch (character)
		{
			case '\\': result += "\\\\"; break;
			case '"': result += "\\\""; break;
			case '\n': result += "\\n"; break;
			case '\r': result += "\\r"; break;
			case '\t': result += "\\t"; break;
			default:
				if (character >= 0x20)
					result.push_back(static_cast<char>(character));
				break;
		}
	}
	return result;
}
}

int main()
{
	const auto plan = vip_database::BuildMigrationPlan();
	std::cout << "{\"migration_version\":\"" << vip_database::kMigrationVersion
		<< "\",\"migration_checksum\":\"" << vip_database::kMigrationChecksum
		<< "\",\"lock_expression\":\"" << JsonEscape(plan.lockQuery)
		<< "\",\"release_lock_expression\":\"" << JsonEscape(plan.releaseLockQuery)
		<< "\",\"ordered_steps\":[";
	for (std::size_t index = 0; index < plan.steps.size(); ++index)
	{
		if (index != 0)
			std::cout << ',';
		const auto &step = plan.steps[index];
		std::cout << "{\"name\":\"" << JsonEscape(step.name)
			<< "\",\"sql\":\"" << JsonEscape(step.sql)
			<< "\",\"is_ddl\":" << (step.isDDL ? "true" : "false")
			<< ",\"idempotent\":" << (step.idempotent ? "true" : "false") << '}';
	}
	std::cout << "]}\n";
	return 0;
}
