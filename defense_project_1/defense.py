import re
import streamlit as st
import mysql.connector
from mysql.connector import Error
import hashlib
import pandas as pd
from sklearn.neighbors import NearestNeighbors  # Import KNN

# Initialize session state variables if they don't exist
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'current_user' not in st.session_state:
    st.session_state['current_user'] = None

# Load the DataFrame globally
df = pd.read_csv("fifaratings.csv")


# Function to connect to MySQL database
def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='manazer_db',
            user='root',  # Update with your MySQL username
            password=''  # Update with your MySQL password
        )
        if connection.is_connected():
            return connection
    except Error as e:
        st.error(f"Error while connecting to MySQL: {e}")
        return None


# Function to hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function to validate email format
def is_valid_email(email):
    email_regex = r'^[a-z0-9._%+-]+@gmail\.com$'
    return re.match(email_regex, email) is not None


# Function to validate password format
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


# Function to validate full name
def is_valid_full_name(full_name):
    full_name_regex = r'^[A-Za-z\s]{4,}$'
    return re.match(full_name_regex, full_name) is not None


# Function to register a new user
def register_user(email, password, full_name, weight, height, age, exercise_time, bed_time, working_time,
                  football_time):
    try:
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            hashed_password = hash_password(password)  # Hash the password
            query = """
            INSERT INTO users (email, password, full_name, weight, height, age, exercise_time, bed_time, working_time, football_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            data = (email, hashed_password, full_name, weight, height, age, exercise_time, bed_time, working_time,
                    football_time)
            cursor.execute(query, data)
            connection.commit()
            st.info(f"Registered user: {email}")  # Debug message
            return True
        else:
            st.error("Failed to connect to the database.")
    except Error as e:
        st.error(f"Error while registering user: {e}")
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()


# Function to authenticate user login
def authenticate_user(email, password):
    try:
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            query = "SELECT * FROM users WHERE email = %s"
            data = (email,)
            cursor.execute(query, data)
            user = cursor.fetchone()
            if user:
                # Check if password matches
                hashed_password = hash_password(password)
                if user[2] == hashed_password:  # Assuming password is stored as hashed in the database
                    return user
            return None
    except Error as e:
        st.error(f"Error while authenticating user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def login_register_page():
    st.title("Login/Register")
    option = st.radio("Select an option:", ["Login", "Register"])

    if option == "Login":
        email = st.text_input("Email:")
        password = st.text_input("Password:", type="password")
        if st.button("Login"):
            user = authenticate_user(email, password)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['current_user'] = user
                st.success("Login Successful!")
                st.experimental_rerun()
            else:
                st.error("Login Failed. Please check your credentials.")

    elif option == "Register":
        email = st.text_input("Email:").strip().lower()
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")
        full_name = st.text_input("Full Name:").strip()
        weight = st.number_input("Weight (kg):", min_value=1.0)
        height = st.number_input("Height (feet-inch):", min_value=1.0)
        age = st.number_input("Age:", min_value=1)
        exercise_time = st.number_input("Exercise Time (hours/day):")
        bed_time = st.number_input("Bed Time (hours/day):")
        working_time = st.number_input("Working Time (hours/day):")
        football_time = st.number_input("Football Time (hours/day):")

        if st.button("Register"):
            if not is_valid_email(email):
                st.error("Invalid email format. Please use a valid @gmail.com address in lowercase.")
            elif not is_valid_password(password):
                st.error(
                    "Password must be at least 8 characters long and include at least one special character and one digit.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            elif not is_valid_full_name(full_name):
                st.error("Full Name must be at least 4 characters long and contain only letters and spaces.")
            elif weight < 1 or height < 1 or age < 1:
                st.error("Enter your information carefully. Weight, height, and age must be at least 1 or more.")
            else:
                if register_user(email, password, full_name, weight, height, age, exercise_time, bed_time, working_time,
                                 football_time):
                    st.success("Registration Successful!")
                else:
                    st.error("Registration Failed. Please try again.")


# Logout function
def logout():
    st.session_state['logged_in'] = False
    st.session_state['current_user'] = None
    st.experimental_rerun()


# Page for Find Position using KNN
def find_position():
    st.subheader("Find POSITION")

    st.text("Rate yourself between 1 and 100 for the following statistics:")

    stats = [
        "Overall", "Potential", "Pace Total", "Shooting Total", "Passing Total",
        "Dribbling Total", "Defending Total", "Physicality Total", "Crossing",
        "Finishing", "Freekick Accuracy", "BallControl", "Acceleration", "Reactions",
        "Balance", "Shot Power", "Stamina", "Vision", "Penalties", "Marking",
        "Goalkeeper Diving", "Goalkeeper Handling", " GoalkeeperKicking", "Goalkeeper Reflexes"
    ]

    user_inputs = {}
    for stat in stats:
        user_inputs[stat] = st.slider(f"{stat}:", min_value=1, max_value=100, value=50)

    if st.button("Submit"):
        user_data = pd.DataFrame([user_inputs])

        # Select the relevant stats columns from the dataset
        knn_data = df[stats]

        # Fit KNN model
        knn = NearestNeighbors(n_neighbors=1)
        knn.fit(knn_data)

        # Find the closest match
        distances, indices = knn.kneighbors(user_data)
        best_match = df.iloc[indices[0][0]]

        st.subheader("Output:")
        st.text(f"Position: {best_match['Best Position']}")
        st.text(f"Name: {best_match['Full Name']}")
        st.text(f"Age: {best_match['Age']}")
        st.text(f"Nationality: {best_match['Nationality']}")
        st.text(f"Overall: {best_match['Overall']}")
        st.image(best_match['Image Link'], caption="Player Image")


# Page for Find Similar Player
def find_similar_player():
    st.subheader("Find SIMILAR PLAYER")

    positions = ["Forward", "Middle", "Backward"]
    preferred_position = st.selectbox("Preferred Position:", positions)

    # conditions
    if preferred_position in ["Forward", "Middle", "Backward"]:
        stats = ["Pace Total", "Shooting Total", "Passing Total", "Dribbling Total",
                 "Physicality Total", "Crossing", "Finishing", "Freekick Accuracy", "BallControl",
                 "Acceleration", "Reactions", "Balance", "Shot Power", "Stamina", "Vision", "Penalties", "Marking"]

    else:
        stats = []
    user_inputs = {}
    for stat in stats:
        user_inputs[stat] = st.slider(f"{stat}:", min_value=1, max_value=100, value=50)

    # Prepare user data for KNN
    user_data = pd.DataFrame([user_inputs])

    # Select the relevant stats columns from the dataset
    knn_data = df[stats]

    # Fit KNN model
    knn = NearestNeighbors(n_neighbors=1)
    knn.fit(knn_data)

    if st.button("Submit"):
        # Find the closest match
        distances, indices = knn.kneighbors(user_data)
        best_match = df.iloc[indices[0][0]]

        st.subheader("Output:")

        # Display the comparison table
        comparison_stats = ["Pace Total", "Shooting Total", "Passing Total", "Dribbling Total",
                 "Physicality Total", "Crossing", "Finishing", "Freekick Accuracy", "BallControl",
                 "Acceleration", "Reactions", "Balance", "Shot Power", "Stamina", "Vision", "Penalties", "Marking"]
        comparison_data = {
            "Stat": comparison_stats,
            "User Data": [user_inputs[stat] for stat in comparison_stats],
            "Similar Player": [best_match[stat] for stat in comparison_stats]
        }
        comparison_df = pd.DataFrame(comparison_data)

        col1, col2 = st.columns(2)

        with col1:
            st.image(best_match['Image Link'], caption="Similar Player")
            st.text(f"Position: {best_match['Best Position']}")
            st.text(f"Name: {best_match['Full Name']}")
            st.text(f"Age: {best_match['Age']}")
            st.text(f"Nationality: {best_match['Nationality']}")
            st.text(f"Overall: {best_match['Overall']}")
            st.text(f"Potential: {best_match['Potential']}")

        with col2:
            st.subheader("User Data")
            st.write(user_data.T)

        st.subheader("Comparison")
        st.table(comparison_df)


# Page for Know Player
def know_player():
    st.subheader("KNOW PLAYER")
    player_names = df['Known As']
    selected_player = st.selectbox("Select a player:", player_names)
    selected_row = df[df['Known As'] == selected_player]

    if st.button("Show Player Data"):
        st.subheader(f"Player Details: {selected_player}")
        st.text(f"Name: {selected_row['Full Name'].values[0]}")
        st.text(f"Age: {selected_row['Age'].values[0]}")
        st.text(f"Overall: {selected_row['Overall'].values[0]}")
        st.text(f"Potential: {selected_row['Potential'].values[0]}")
        st.text(f"Pace Total: {selected_row['Pace Total'].values[0]}")
        st.text(f"Passing Total: {selected_row['Passing Total'].values[0]}")
        st.text(f"Shooting Total: {selected_row['Shooting Total'].values[0]}")
        st.text(f"Nationality: {selected_row['Nationality'].values[0]}")

        st.image(selected_row['Image Link'].values[0], caption="Player Image")

    if st.button("Show Full Details"):
        st.write(selected_row)

def comparison_page():
   # st.title("Comparison")

    # User inputs
    st.subheader("Comparison With Your Dream Player:")
    user_name = st.text_input("Enter your name:")

    user_inputs = {}
    for stat in ["Pace Total", "Shooting Total", "Passing Total", "Dribbling Total", "Physicality Total",
                 "Crossing", "Finishing", "Freekick Accuracy", "BallControl", "Acceleration", "Reactions",
                 "Balance", "Shot Power", "Stamina", "Vision", "Penalties", "Marking"]:
        user_inputs[stat] = st.slider(stat, min_value=1, max_value=100, value=50)

    # Dream Player selection
    st.subheader("Select Dream Player")
    dream_player_options = df['Known As'].tolist()
    selected_dream_player = st.selectbox("Select a Dream Player:", dream_player_options)

    if st.button("Compare"):
        # Fetch data for selected dream player
        dream_player_data = df[df['Known As'] == selected_dream_player].squeeze()

        # Prepare comparison data
        comparison_stats = ["Pace Total", "Shooting Total", "Passing Total", "Dribbling Total", "Physicality Total",
                            "Crossing", "Finishing", "Freekick Accuracy", "BallControl", "Acceleration", "Reactions",
                            "Balance", "Shot Power", "Stamina", "Vision", "Penalties", "Marking"]
        comparison_data = {
            "Stat": comparison_stats,
            "User Data": [user_inputs[stat] for stat in comparison_stats],
            "Dream Player": [dream_player_data[stat] for stat in comparison_stats]
        }
        comparison_df = pd.DataFrame(comparison_data)

        # Display comparison table
        st.subheader("Comparison Result:")
        st.table(comparison_df)


# Main option page
def option_page():
    st.title("OPTIONS")
    option = st.radio("Choose an option:", ["Find POSITION", "Find SIMILAR PLAYER", "KNOW PLAYER", "COMPARISON", "LOGOUT"])

    if option == "Find POSITION":
        find_position()
    elif option == "Find SIMILAR PLAYER":
        find_similar_player()
    elif option == "KNOW PLAYER":
        know_player()
    elif option =="COMPARISON":
        comparison_page()
    elif option == "LOGOUT":
        logout()

# Main function to run the app
def main():
    if st.session_state['logged_in']:
        option_page()
    else:
        login_register_page()


if __name__ == "__main__":
    main()

