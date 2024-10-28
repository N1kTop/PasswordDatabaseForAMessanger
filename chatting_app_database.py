## Password database for a potential chat-bot
# Author: Nik Topolskis
# Date: 15/09/2024
# Version 1.3

# Description:
# Allows users to create and manage their accounts
# where they can access chat messages with other users.
# The program focuses on security and the chat-bot feature is not the priority.
# All passwords are hashed and stored in an SQL database along with salt for every user.
# Password policy is in place.
# Multiple incorrect guesses forces the user to complete a CAPTCHA.
# The program also keeps track of logs of all events,
# eg. log-ins, sign-ups, password resets...
# The program uses command line interface

import sqlite3, hashlib, requests, random, time, sys
from captcha.image import ImageCaptcha
from PIL import Image

# Define different character sets for password complexity
CHARACTERS :str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]{}!@#$%^&*()_+-=~`|"
ALPHA_NUMERICAL :str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
CAPITAL_NUMERICAL :str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS :str = "0123456789"
SPECIAL :str = ",./;'[]{}!@#$%^&*()_+-=~`|"

account :str = None # current signed-in account
attempts :int = 0 # number of log-in attempts

# Captcha generation setup
image = ImageCaptcha(fonts=['captcha.ttf'])

# Converts a string to an integer safely
def convertToInt(s :str):
    res = 0
    try:
        res =  int(s)
    finally:
        return res

# Executes a SQL query with data and returns all results
def processQuery(query, data):
    return cur.execute(query, data).fetchall()

# Executes a SQL query without any data input
def processQuery(query):
    return cur.execute(query).fetchall()

# Deletes a user from the Users table by username
def deleteUser(username):
    data = (username,)
    cur.execute("DELETE FROM Users WHERE username = ?;", data)

# Generates a random 16-character salt
def generateSalt():
    newSalt = ""
    for i in range(16):
        newSalt += random.choice(CHARACTERS)
    return bytes(newSalt, "utf-8")

# Hashes the password using SHA-256 with salt
def hashPassword(password :str, salt :str):
    return hashlib.sha256(password + salt).hexdigest()

# Returns the next user ID by finding the max ID and incrementing
def nextUserId() -> int:
    max_id = cur.execute("""
        SELECT max(id)
        FROM Users
    """).fetchall()[0][0]
    if max_id is None:
        return 1
    return max_id + 1

# Adds a new user to the Users table with username, hashed password, and salt
def addUser(username :str, hash, salt :str, isAdmin :bool):
    data = (nextUserId(), username, hash, salt, isAdmin,)

    cur.execute("""
        INSERT INTO Users VALUES
        (?, ?, ?, ?, NULL, ?)
    """, data)

# Removes a user from the Users table
def removeUser(username :str):
    data = (username,)
    cur.execute("""
        DELETE FROM Users
        WHERE Username = ?
    """, data)

# Updates the password hash for a user
def updateHash(username :str, newHash):
    data = (newHash, username,)
    cur.execute("""
    UPDATE Users
    SET hash = ?
    WHERE username = ?
    """, data)

# Updates a user's username in the Users table
def updateUsername(username :str, newName :str):
    data = (newName, username,)
    cur.execute("""
    UPDATE Users
    SET username = ?
    WHERE username = ?
    """, data)

# Updates a user's email in the Users table
def updateEmail(username :str, newEmail :str):
    data = (newEmail, username,)
    cur.execute("""
    UPDATE Users
    SET email = ?
    WHERE username = ?
    """, data)

# Returns all users from the Users table
def allUsers():
    return cur.execute("SELECT * FROM Users").fetchall()

# Prints details of all users in the Users table
def printAllUsers():
    for record in allUsers():
        print("\n")
        print(*record)

# Displays a user's friends list by querying the Relationships table
def viewFriendsList(user_id :int):
    friends1 = cur.execute("""
        SELECT user1_id
        FROM Relationships
        WHERE user2_id = ?
        AND user1_status = "friend" AND user2_status = "friend"
    """, (user_id,)).fetchall()
    friends2 = cur.execute("""
        SELECT user2_id
        FROM Relationships
        WHERE user1_id = ?
        AND user1_status = "friend" AND user2_status = "friend"
    """, (user_id,)).fetchall()

    dict = {}
    count = 1
    print("\n")

    for friend in friends1:
        print(count, getUsername(friend[0]))
        dict[count] = friend[0]
        count += 1
    for friend in friends2:
        print(count, getUsername(friend[0]))
        dict[count] = friend[0]
        count += 1
    return dict

# Creates the Users table in the database
def createUsersTable():
    cur.execute("CREATE TABLE Users(id INT, username, hash , salt, email, admin BOOLEAN)")

# Creates the Logs table in the database
def createLogsTable():
    cur.execute("CREATE TABLE Logs(id INT, event, user_id INT, username, outcome BOOLEAN, datetime)")

# Creates the Relationships table in the database
def createRelationshipsTable():
    cur.execute("CREATE TABLE Relationships(user1_id INT, user2_id INT, user1_status, user2_status)")

# Creates the Chat table in the database for user-to-user chat sessions
def createChatTable():
    cur.execute("CREATE TABLE Chat(id INT, user1_id INT, user2_id INT)")

# Creates the Messages table in the database to store chat messages
def createMessagesTable():
    cur.execute("CREATE TABLE Messages(chat_id INT, user_id INT, message)")

# Adds a new message to a chat
def createChat(user1_id :int, user2_id :int):
    data = (nextChatId(), user1_id, user2_id)
    cur.execute("""
        INSERT INTO Chat
        VALUES(?, ?, ?)
    """, data)

# Gets names of every table in the database
def getTablesNames():
    return cur.execute("SELECT name FROM sqlite_master").fetchall()

# Creates tables if database is empty
def dbSetup():
    if len(getTablesNames()) == 0:
        createUsersTable()
        createLogsTable()
        createRelationshipsTable()
        createChatTable()
        createMessagesTable()

# Finds an existing chat between two users or returns None if it doesn't exist
def findChat(user1_id :int, user2_id :int):
    data = (user1_id, user2_id, user2_id, user1_id,)
    chatRequest = cur.execute("""
        SELECT id
        FROM Chat
        WHERE user1_id = ? AND user2_id = ?
        OR user1_id = ? AND user2_id = ?
    """, data).fetchall()
    if len(chatRequest) == 0:
        return None
    return chatRequest[0][0]

# Fetches all chats from the Chat table
def getChats():
    return cur.execute("SELECT * FROM Chat").fetchall()

# Fetches all chats involving a particular user
def getUserChats(user_id :int):
    data = (user_id, user_id,)
    return cur.execute("""
        SELECT *
        FROM Chat
        WHERE user1_id = ?
        OR user2_id = ?
    """, data).fetchall()

# Displays a list of chats involving a particular user
def viewChats(user_id :int):
    chats = getUserChats(user_id)
    count = 1
    for chat in chats:
        print(count, getUsername(chat[1]), getUsername(chat[2]))
        count += 1

    return chats

# Adds a message to the Messages table for a specific chat
def addMessage(chat_id :int, user_id :int, message :str):
    data = (chat_id, user_id, message)
    cur.execute("""
        INSERT INTO Messages
        VALUES (?, ?, ?)
    """, data)

# Fetches the users involved in a specific chat
def getChatters(chat_id :int):
    people = cur.execute("""
        SELECT user1_id, user2_id
        FROM Chat
        WHERE id = ?
    """, (chat_id,)).fetchall()
    dict = {}
    for person in people:
        dict[person[0]] = getUsername(person[0])
        dict[person[1]] = getUsername(person[1])
    return dict

# Prints all messages from a specific chat, displaying the username alongside each message
def printMessages(chat_id :int):
    dict = getChatters(chat_id)
    messages = cur.execute("""
        SELECT message, user_id
        FROM Messages
        WHERE chat_id = ?
    """, (chat_id,)).fetchall()
    if len(messages) == 0:
        print("chat not found\n")
        return
    for message in messages:
        print(dict[message[1]] + ": " + message[0])

# Reads and prints messages from a specific chat
def readMessages(chat_id :int):
    messages = cur.execute("""
        SELECT message, user_id
        FROM Messages
        WHERE chat_id = ?
    """, (chat_id,))
    for message in messages:
        print(*message)

# Prints chats of a user by querying for both chat sides (user1 and user2)
def printUserChats(user_id :int):
    chats1 = cur.execute("""
        SELECT id, user1_id
        FROM Chats
        WHERE user2_id = ?
    """, (user_id,)).fetchall()
    chats2 = cur.execute("""
        SELECT id, user2_id
        FROM Chats
        WHERE user1_id = ?
    """, (user_id,)).fetchall()
    for chat in chats1:
        print(*chat)
    for chat in chats2:
        print(*chat)

# Returns the next available Logs ID
def nextLogsId() -> int:
    max_id = cur.execute("""
        SELECT max(id)
        FROM Logs
    """).fetchall()[0][0]
    if max_id is None:
        return 1
    return max_id + 1

# Returns the next available Chat ID
def nextChatId() -> int:
    max_id = cur.execute("""
        SELECT max(id)
        FROM Chat
    """).fetchall()[0][0]
    if max_id is None:
        return 1
    return max_id + 1

# Logs an event (like log-in, sign-up, etc.) into the Logs table
def logEvent(event :str, user_id :int, username :str, outcome :bool):
    data = (nextLogsId(), event, user_id, username, outcome, time.ctime())
    cur.execute("""
        INSERT INTO Logs VALUES
        (?, ?, ?, ?, ?, ?)
    """, data)

# Fetches all logs from the Logs table
def getLogs():
    return cur.execute("""
        SELECT *
        FROM Logs
    """).fetchall()

# Prints all the logs in the Logs table
def printLogs():
    for log in getLogs():
        print("\n")
        print(*log)

# Checks if a user exists in the Users table by username
def userExists(username :str) -> bool:
    data = (username,)
    same_name = cur.execute("""
        SELECT *
        FROM Users
        WHERE username = ?
    """, data).fetchall()
    return len(same_name) > 0

# Allows a new user to sign up, ensuring unique usernames
def newUser():
    name = input("\nUsername: ")

    # get input until username is valid:
    while userExists(name) and name != "0":
        print("That username already exists")
        name = input("\nUsername: ")
        return
    if name == "0":
        print("Sign-Up canceled")
        return

    password = createPassword(name)
    if password == 0:
        print("Sign-Up canceled")
        logEvent("sign-up", nextUserId(), name, False)
        return

    salt = generateSalt()
    hash = hashPassword(bytes(password, "utf-8"), salt)
    addUser(name, hash, salt, False)
    logEvent("sign-up", nextUserId(), name, True)
    print("\nSuccessfully created user " + name)

# Retrieves the salt for a user by querying the Users table
def getSalt(username :str):
    data = (username,)
    saltRequest = cur.execute("SELECT salt FROM Users WHERE username = ?", data).fetchall()
    if len(saltRequest) == 0:
        return None
    return saltRequest[0][0]

# Retrieves the user ID based on the username
def getId(username :str):
    data = (username,)
    idRequest = cur.execute("SELECT id FROM Users WHERE username = ?", data).fetchall()
    if len(idRequest) == 0:
        return None
    return idRequest[0][0]

# Retrieves the username based on the user ID
def getUsername(id :int):
    data = (id,)
    usernameRequest = cur.execute("SELECT username FROM Users WHERE id = ?", data).fetchall()
    if len(usernameRequest) == 0:
        return None
    return usernameRequest[0][0]

# Handles password creation with guidelines to ensure strong passwords
def createPassword(username :str):
    strong :bool = False

    print("\nChoose a password")

    text = """
    - Your password should be at least 12 characters long
    - Your password must include both lowercase and uppercase letters
    - Password should include a number and a special character
    - Your password should not be your username
    - Your password should not be a word or predictable set of characters
    - Type 0 to cancel
    """
    print(text)

    while (not strong):
        password = input("\nPassword: ")
        if password == "0":
            return 0

        if len(password) < 12:
            print("\nYour password is less than 12 characters long")
            continue
        if password == username:
            print("\nYour password is the same as your username")
            continue

        # variables to keep track of characters in a password:
        special = False
        lowercase = False
        uppercase = False
        digit = False

        # check each character in the password
        for char in password:
            if not lowercase and char.islower():
                lowercase = True
            elif not uppercase and char.isupper():
                uppercase = True
            elif not digit and char in DIGITS:
                digit = True
            elif not special and char in SPECIAL:
                special = True

        if special and lowercase and uppercase and digit:
            strong = True
            continue

        message = "\nYour password does not include: |"

        if not lowercase:
            message += " a lowercase letter |"
        if not uppercase:
            message += " an uppercase letter |"
        if not digit:
            message += " a digit |"
        if not special:
            message += " a special character |"

        print(message)

    return password


# Handles user login by verifying the username and password hash
# Return true or false based on logIn success
# If successful, changes account name
def logIn() -> bool:
    name = input("\nUsername: ")
    password = input("Password: ")

    # get salt from database:
    data = (name,)
    saltRequest = cur.execute("""
        SELECT salt
        FROM Users
        WHERE username = ?
    """, data).fetchall()
    if len(saltRequest) < 1:
        print("Wrong details")
        return False
    salt = saltRequest[0][0]


    hash = hashPassword(bytes(password, "utf-8"), salt)

    data = (name, hash,)
    res = cur.execute("""
        SELECT *
        FROM Users
        WHERE username = ?
        AND hash = ?
    """, data)

    if res.fetchone() is None:
        print("Wrong details")
        logEvent("log-in", getId(name), name, False)
        return False
    print("Welcome,", name + "!")

    global account
    account = name
    logEvent("log-in", getId(name), name, True)
    return True

# Prints the details of a user, including ID, username, email, and admin status
def printUserDetails(username :str):
    data = (username,)
    res = cur.execute("""
        SELECT id, username, email, admin
        FROM Users
        WHERE username = ?
    """, data).fetchall()

    if len(res) == 0:
        return

    userData = res[0]

    id = userData[0]
    username = userData[1]
    email = userData[2]

    print("\nUser ID: " + str(id))
    print("Username: " + username)
    if not email is None:
        print("Email: " + email)
    if userData[3]:
        print("ADMIN")

# Checks if a user is an admin
def isAdmin(username :str):
    data = (username,)
    return cur.execute("""
        SELECT admin
        FROM Users
        WHERE username = ?
    """, data).fetchall()[0][0]

# Allows a user to change their username
def changeUsername(username :str):
    newName = input("\nUsername: ")

    while userExists(newName) and newName != "0":
        print("That username already exists")
        newName = input("\nUsername: ")
        return
    if newName == "0":
        print("Canceled")
        logEvent("username change", getId(username), username, False)
        return

    updateUsername(username, newName)
    print("\nSuccessfully changed name to " + newName)
    logEvent("username change", getId(newName), newName, True)

# Allows a user to change their password
def changePassword(username :str):
    newPassword = createPassword(username)
    if newPassword == 0:
        print("Password update canceled")
        logEvent("password change", getId(name), name, False)
        return

    salt = getSalt(username)
    hash = hashPassword(bytes(newPassword, "utf-8"), salt)
    updateHash(username, hash)
    print("\nSuccessfully changed password")
    logEvent("password change", getId(username), username, True)

# Allows a user to change their email
def changeEmail(username :str):
    newEmail = input("\nEmail: ")
    updateEmail(username, newEmail)
    print("\nSuccessfully changed email to " + newEmail)
    logEvent("email change", getId(username), username, True)

# Allows a user to delete their account after confirming the action
def deleteAccount(username :str) -> bool:
    choice = input("Do you want to delte this accoutn permanently? ")

    if len(choice) > 0 and choice[0] == "y":
        removeUser(username)
        print("Account " + username + " was deleted")
        logEvent("account deletion", getId(username), username, True)
        return True
    logEvent("account deletion", getId(username), username, False)
    return False

# Allows a user to recover their password by sending a recovery code via email
def forgotPassword():
    name = input("\nUsername: ")
    data = (name,)
    emailRequest = cur.execute("""
        SELECT email
        FROM Users
        WHERE username = ?
    """, data).fetchall()

    if len(emailRequest) == 0:
        print("\nUnfortunately, that account does not have an email asociated with it")
        return
    email = emailRequest[0][0]

    if email is None:
        print("\nUnfortunately, that account does not have an email asociated with it")
        return

    # generate code:
    code = ""
    for i in range(16):
        code += random.choice(ALPHA_NUMERICAL)

    # if email not sent:
    if sendRecoveryCode(email, code) == None:
        print("\nCould not send the code, check Wi-Fi connection and try again")
        return
    print("\nRecovery code has been sent to your email")
    answer = input("Code: ")
    if code != answer:

        print("The code does not match")
        logEvent("password reset", getId(name), name, False)
        return

    logEvent("password reset", getId(name), name, True)
    changePassword(name)

# Sends recovery code via email, feature is removed
def sendRecoveryCode(email :str, code :str):
    print("\nThis feature was temporarily removed\n")
    return None

# Generates and displays a CAPTCHA that the user must solve before continuing
def solveCaptcha() -> bool:
    print("\nYou must solve the captcha to continue")
    cap :str = generateCaptcha()
    data = image.generate(cap)
    image.write(cap, 'out.png')
    im = Image.open("out.png")
    im.show()
    answer = input("Enter captcha: ").upper()
    return cap == answer

# Generates a CAPTCHA string of 8 uppercase alphanumeric characters
def generateCaptcha():
    cap = ""
    for i in range(8):
        cap += random.choice(CAPITAL_NUMERICAL)
    return cap

# Handles login attempts, including CAPTCHA verification if there are 5 or more failed attempts
def logInAttempt():
    global attempts
    if attempts >= 5:
        if not solveCaptcha():
            print("The captcha does not match")
            return

    if logIn():
        attempts = 0
    else:
        attempts += 1

# User interface for logging in or signing up
def loginInterface():
    while True:
        print("""
        (1) Log-In
        (2) Sign-Up
        (3) Forgot Password
        (4) Exit
        """)
        choice = input("Enter number: ")
        if choice == "1":
            logInAttempt()
            if account is None:
                continue
            menuInterface()
        elif choice == "2":
            newUser()
        elif choice == "3":
            forgotPassword()
        elif choice == "4":
            return

# Menu interface for managing user account settings
def accountMenu():
    global account

    message = """
        (1) Inspect details
        (2) Change username
        (3) Change password
        (4) Change email
        (5) Delete account
        (6) Back
        """

    if isAdmin(account):
        message += "(0) Admin console\n"

    while True:
        print(message)
        choice = input("Enter number: ")
        if choice == "1":
            printUserDetails(account)
        elif choice == "2":
            changeUsername(account)
        elif choice == "3":
            changePassword(account)
        elif choice == "4":
            changeEmail(account)
        elif choice == "5":
            if deleteAccount(account):
                account == None
                return
        elif choice == "6":
            return
        elif choice == "0" and isAdmin(account):
            adminMenu()

# Admin console for viewing logs and managing users
def adminMenu():
    while True:
        print("""
        (1) Logs
        (2) Users
        (3) Back
        """)
        choice = input("Enter number: ")
        if choice == "1":
            print("\nLogs:")
            print("# event id username datetime")
            printLogs()
        elif choice == "2":
            print("\nUsers:")
            adminUsersMenu()
        elif choice == "3":
            return

# Admin menu for selecting and managing users
def adminUsersMenu():
    print("id username email admin")
    displayUsers()
    print("\n")
    while True:
        print("""
        (1) Select user by ID
        (2) Select user by username
        (3) Back
        """)
        choice = input("Enter number: ")
        if choice == "1":
            id = input("ID: ")
            userModMenu("id", id)
        elif choice == "2":
            username = input("Username: ")
            userModMenu("username", username)
        elif choice == "3":
            return

# Allows admins to manage a specific user based on user ID or username
def userModMenu(type :str, user :str):
    if (type == "id"):
        usernameRequest = cur.execute("SELECT username FROM Users WHERE id = ?", (user,)).fetchall()
        if len(usernameRequest) == 0:
            print("User not found")
            return
        user = usernameRequest[0][0]
    elif not userExists(user):
        print("User not found")
        return

    print("\n" + user)

    while True:
        print("""
        (1) User logs
        (2) Change password
        (3) Change email
        (4) Back
        """)
        choice = input("Enter number: ")
        if choice == "1":
            userLogs(user)
        elif choice == "2":
            changePassword(user)
        elif choice == "3":
            changeEmail(user)
        elif choice == "4":
            return


# Handles sending a text message to a friend
def textFriend():
    friends = viewFriendsList(getId(account))
    count = 0
    for friend in friends:
        count += 1
    # choose user index:
    choice = input("\nEnter number or 0 to cancel: ")
    intChoice = convertToInt(choice)
    if choice == 0:
        return
    if intChoice < 1 or intChoice > count:
        print("Chat not found\n")
        return

    user1_id = getId(account)
    user2_id = friends[intChoice]

    chat_id = findChat(user1_id, user2_id)

    if chat_id == None:
        createChat(user1_id, user2_id)
        enterChat(chat_id)
    else:
        enterChat(chat_id)


# Menu for managing user chats
def chatsMenu():
    print("\n")
    chats = viewChats(getId(account))
    count = 0
    for chat in chats:
        count += 1
    choice = input("\nEnter chat number or 0 to cancel: ")
    intChoice = convertToInt(choice)
    # verify choice:
    if choice == 0:
        return
    if intChoice < 0 or intChoice > count:
        print("Chat not found\n")
        return

    enterChat(chats[intChoice - 1][0])

# Allows users to enter and interact in a specific chat
def enterChat(chat_id :int):
    user_id = getId(account)
    printMessages(chat_id)
    while True:
        message = input(account + ": ")
        if message == "0":
            return
        addMessage(chat_id, user_id, message)

# Menu for creating or selecting chats with friends
def newChatMenu():
    username = input("Username: ")
    if username == "0":
        return
    if not userExists(username):
        print("That user does not exist")
        return
    user1_id = getId(account)
    user2_id = getId(username)

    chat_id = findChat(user1_id, user2_id)

    if chat_id == None:
        createChat(user1_id, user2_id)
        enterChat(chat_id)
    else:
        enterChat(chat_id)

# Message menu for interacting with chats and friends
def messageMenu():
    while True:
        print("""
        (1) Chats
        (2) New chat
        (3) Text a friend
        (4) Back
        """)
        choice = input("Enter number: ")
        if choice == "1":
            chatsMenu()
        elif choice == "2":
            newChatMenu()
        elif choice == "3":
            textFriend()
        elif choice == "4":
            return

# Main menu interface for user actions like managing messages, friends, and account settings
def menuInterface():
    global account
    while True:
        print("""
        (1) Messages
        (2) Add Friend
        (3) Account settings
        (4) Log-Out
        """)
        choice = input("Enter number: ")
        if choice == "1":
            messageMenu()
        elif choice == "2":
            addFriendMenu()
        elif choice == "3":
            accountMenu()
        elif choice == "4":
            account = None
            return

# Menu for adding a new friend by username
def addFriendMenu():
    print("\nEnter friend's username or 0 to cancel'")
    friendUsername = input("Username: ")
    addFriend(account, friendUsername)

# Adds a friend to the user's friend list by updating or creating a relationship
def addFriend(username1 :str, username2 :str):
    user1_id = getId(username1)
    user2_id = getId(username2)

    # updates status if relationship exists or creates a new relationship
    if relationshipExists(user1_id, user2_id):
        cur.execute("""
            UPDATE Relationships
            SET user1_status = "friend"
        """)
    elif relationshipExists(user2_id, user1_id):
        cur.execute("""
            UPDATE Relationships
            SET user2_status = "friend"
        """)
    else:
        cur.execute("""
            INSERT INTO Relationships
            VALUES(?, ?, ?, ?)
        """, (user1_id, user2_id, "friend", "none"))
    print("Friend request added")

# Checks if a relationship between two users exists in the Relationships table
def relationshipExists(user1_id: int, user2_id: int) -> bool:
    data = (user1_id, user2_id,)
    ralationshipRequst = cur.execute("""
        SELECT *
        FROM Relationships
        WHERE user1_id = ? AND user2_id = ?
    """, data).fetchall()
    return len(ralationshipRequst) > 0

# Displays the logs of a specific user by querying the Logs table
def userLogs(username: str):
    data = (username,)
    logs = cur.execute("""
        SELECT *
        FROM Logs
        WHERE username = ?
    """, data).fetchall()
    for record in logs:
        print(*record)

# Displays all users in the Users table with their details (ID, username, email, admin status)
def displayUsers():
    users = cur.execute("""
        SELECT id, username, email, admin
        FROM Users
    """).fetchall()
    for record in users:
        print(*record)


def main():
    global con, cur
    con = sqlite3.connect("database.db")    # connect to the SQL database
    cur = con.cursor()                      # initiolize cursor

    dbSetup()                               # setup database tables

    loginInterface()                        # start the menu


    con.commit()                            # save changes to database

    cur.close()
    con.close()                             # close database

if __name__ == "__main__":
    sys.exit(main())
