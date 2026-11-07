"""Unit test ensuring Textual TUI stylesheet and screens instantiate cleanly."""

import unittest
from app.tui.app import (
    AIChatScreen,
    DashboardScreen,
    HistoryScreen,
    LiveScanScreen,
    NewScanScreen,
    ReportViewerScreen,
    RootScanApp,
    SettingsScreen,
    ToolRegistryScreen,
)


class TestTuiApp(unittest.IsolatedAsyncioTestCase):
    def test_app_initialization_and_css(self):
        app = RootScanApp()
        self.assertIsNotNone(app)
        self.assertIn("Screen", app.CSS)
        self.assertNotIn("font-family", app.CSS)

    def test_screen_instantiations(self):
        # Verify all screen classes instantiate without errors
        screens = [
            DashboardScreen(),
            NewScanScreen(),
            LiveScanScreen("test.target", "quick", False),
            HistoryScreen(),
            ReportViewerScreen("SCN-TEST"),
            AIChatScreen("SCN-TEST"),
            ToolRegistryScreen(),
            SettingsScreen()
        ]
        self.assertEqual(len(screens), 8)

    async def test_app_pilot_run(self):
        app = RootScanApp()
        async with app.run_test() as pilot:
            self.assertTrue(app.is_running)


if __name__ == "__main__":
    unittest.main()

