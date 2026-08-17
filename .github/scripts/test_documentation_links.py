"""Contract tests for module README navigation links."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "https://github.com/bywinsty/cs2-vip-modules"
README_NAMES = ("README.md", "README-RU.md", "README-UA.md")
REPOSITORY_LINK = re.compile(
    rf"{re.escape(REPOSITORY)}/(?:blob|tree)/(?P<ref>[^/]+)/"
)


class DocumentationLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = sorted(path for path in ROOT.glob("VIP_*") if path.is_dir())

    def test_all_modules_have_the_three_localized_readmes(self):
        self.assertEqual(len(self.modules), 35)
        for module in self.modules:
            self.assertEqual(
                {path.name for path in module.glob("README*.md")},
                set(README_NAMES),
                module.name,
            )

    def test_repository_links_use_main(self):
        markdown_files = [ROOT / "README.md", ROOT / "README-RU.md", ROOT / "README-UA.md"]
        markdown_files.extend(
            readme for module in self.modules for readme in (module / name for name in README_NAMES)
        )

        for path in markdown_files:
            text = path.read_text(encoding="utf-8")
            refs = [match.group("ref") for match in REPOSITORY_LINK.finditer(text)]
            self.assertTrue(refs, path.relative_to(ROOT))
            self.assertTrue(
                all(ref == "main" for ref in refs),
                f"non-main repository link in {path.relative_to(ROOT)}: {refs}",
            )

    def test_module_headings_point_to_the_matching_main_directory(self):
        for module in self.modules:
            expected = f"{REPOSITORY}/tree/main/{module.name}"
            for name in README_NAMES:
                path = module / name
                self.assertIn(expected, path.read_text(encoding="utf-8"), path)

    def test_root_tables_link_to_every_localized_readme_on_main(self):
        for name in ("README.md", "README-RU.md", "README-UA.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for module in self.modules:
                for readme_name in README_NAMES:
                    expected = f"{REPOSITORY}/blob/main/{module.name}/{readme_name}"
                    self.assertIn(expected, text, f"{name}: {expected}")


if __name__ == "__main__":
    unittest.main()
