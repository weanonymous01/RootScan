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


class TestTuiApp(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
