# Messenger Database

This is a Python-based Messenger application that interacts with an SQLite database for managing user accounts, messaging, and event logs.
The focus of this project is on building a secure user account system with hashed and salted passwords, as well as logging events such as user logins, sign-ups, and password changes.

## Features

_User Authentication:_

Secure sign-up with hashed passwords (SHA-256) and random salt generation.
Log-in system with password verification.
Admin users have elevated privileges for managing logs and users.


_Account Management:_

Change username, password, or email.
Delete accounts permanently.
Password recovery via email with a verification code.


_Messaging System:_

Send messages between users.
View chat history with friends.
Create and manage friend relationships.


_Event Logging:_

Every significant event (sign-up, log-in, password change, etc.) is logged in the database.
Admins can view all logs for users and the system.
Database Schema


## Database

The **SQLite database** consists of the following tables:

_Users Table (Users):_

Stores user information such as ID, username, hashed password, salt, email, and admin status.
Columns: id, username, hash, salt, email, admin


_Logs Table (Logs):_

Logs important system events such as log-ins, sign-ups, and password changes.
Columns: id, event, user_id, username, outcome, datetime


_Relationships Table (Relationships):_

Tracks user friendships. A user can send a friend request or accept/decline friend requests.
Columns: user1_id, user2_id, user1_status, user2_status


_Chat Table (Chat):_

Tracks the creation of user-to-user chats.
Columns: id, user1_id, user2_id


_Messages Table (Messages):_

Stores the actual messages exchanged between users.
Columns: chat_id, user_id, message


**Setup and Installation**

Clone the repository:

`
git clone https://github.com/yourusername/messenger-database.git
cd messenger-database
`

Install required dependencies:

The project relies on some Python libraries like sqlite3, PIL, and requests.

Install them using pip:

`
pip install hashlib
pip install requests
pip install captcha
pip install PIL
`


## Running the Application

Run the program by executing the main script:

`
python chatting_app_database.py
`

The database will be automatically initialized when the program starts if the necessary tables don't exist.
If needed, you can manually create the tables by calling the dbSetup() function in the main() script.

Log-In Interface:
Users can log in or sign up via the terminal interface.

Account Settings:
Users can update their username, password, or email, or delete their account.

Messaging:
Users can start chats with friends, view previous messages, and send new messages.
Users can also add friends by username.

Admin Features:
Admins can view the system logs and manage users, including changing their passwords or emails.


## Security Features

Password Hashing: All passwords are hashed using the SHA-256 algorithm with a randomly generated salt to enhance security.
Captcha Protection: Users are required to solve a CAPTCHA after five failed login attempts to prevent brute-force attacks.
Event Logging: Important actions such as login attempts, password changes, and account deletions are logged to keep track of activity.


## Dependencies

Python 3.x

sqlite3: For database management.

Pillow (PIL): For generating CAPTCHA images.

requests: For sending email recovery codes


## Future Improvements

Network Integration: The current application runs offline. A future goal is to add network support to allow messaging across devices.
Improved UI: The current interface is text-based. A graphical user interface (GUI) could be implemented for a better user experience.
Additional Features: File-sharing, group chats, and message encryption could be added to extend the functionality.
