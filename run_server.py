#!/usr/bin/env python3
"""
LocalCast - Private Network Multimedia Broadcasting Platform
Python Implementation with Flask

This script runs the LocalCast server for private network multimedia broadcasting.
Features include:
- User authentication and authorization
- Role-based access control (Admin, Broadcaster, Moderator, Viewer)
- Stream management and broadcasting
- Network device discovery
- Real-time communication support
- WebRTC signaling server capabilities

Usage:
    python run_server.py

Demo Accounts:
    Admin: admin/admin123
    Broadcaster: teacher/teacher123
    Viewer: student/student123
    Moderator: moderator/mod123

The server will run on http://localhost:5000 by default.
"""

import os
import sys
from app import app, init_db

def main():
    """Main function to run the LocalCast server."""

    print("=" * 60)
    print("🎥 LocalCast - Private Network Broadcasting Platform")
    print("=" * 60)
    print("📡 Multimedia Multicasting System")
    print("🔐 Authentication: Enabled")
    print("👥 Role-Based Access Control: Active")
    print("")
    print("Demo Accounts Available:")
    print("  👑 Admin:       admin/admin123")
    print("  📺 Broadcaster: teacher/teacher123")
    print("  👀 Viewer:      student/student123")
    print("  🛡️  Moderator:   moderator/mod123")
    print("")
    print("Features:")
    print("  ✅ User Authentication & Authorization")
    print("  ✅ Live Stream Broadcasting")
    print("  ✅ Multi-user Stream Viewing")
    print("  ✅ Network Device Management")
    print("  ✅ Real-time Communication")
    print("  ✅ Bandwidth Optimization")
    print("  ✅ Private Network Operation")
    print("")
    print("🌐 Server starting on http://localhost:5000")
    print("🔧 Debug mode: Enabled")
    print("=" * 60)

    # Initialize database and demo data
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        sys.exit(1)

    # Set environment variables if not already set
    if not os.getenv('FLASK_ENV'):
        os.environ['FLASK_ENV'] = 'development'

    if not os.getenv('FLASK_DEBUG'):
        os.environ['FLASK_DEBUG'] = '1'

    try:
        # Run the Flask application
        app.run(
            debug=True,
            host='0.0.0.0',  # Allow connections from any IP on the local network
            port=5000,
            threaded=True    # Enable threading for concurrent connections
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
