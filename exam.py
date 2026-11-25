# Imports our modules
import requests # Requests allows us to requests our data from the API 
import json # JSON is used to load the fetched data as a dictionary
import time # Time is used to pause between requests, avoiding rate limits
import logging # Logging is used to log our progress in a file instead of the terminal
import sqlite3 # SQLite3 is being used to construct our database
import dotenv # allows us to connect to our env file and loads it into the enviroment
import os  # OS allows us to read the enviroment variables (Locally saved token)

logger = logging.getLogger("") # Setups our logging
logging.basicConfig(filename="info.log", level=logging.INFO, encoding="utf-8",
                format="%(asctime)s %(levelname)s %(message)s") # Points logger at our logfile

dotenv.load_dotenv("SavedToken.env") # Connects to the env file with our token

API_BASE = "http://164.90.176.250" # The API we're connecting to
EMAIL = "laki1000@stud.ek.dk" # User email for fetching token
TRACKER = 0 # Ensures we can catch persistent errors

def get_incidents(): # This function gets our incidents
    url = f"{API_BASE}/api/incidents?$skip=0&$top=100" # Creates our URL
    allrecords = [] # Setups a list for containing data
    while True: # Uses a while loop to fetch all the pages
        token = os.getenv("TOKEN") # Loads our token from our env file
        headers = {"Authorization": f"Bearer {token}"} # Formats our token for the API
        try:
            response = requests.get(url, headers=headers, timeout=300) # Attempts to connect
            statuscode = response.status_code
            if statuscode == 200: # Statuscode 200 = Succesful connection
                json_data = json.loads(response.text) # Loads the fetched data
                allrecords.append(json_data) # Adds the data to our list
                if json_data["pagination"]["skip"] == 0: # Tracks progress in our log
                    logger.info("Current fetched page: 1") 
                else:
                    logger.info(f"Current fetched page: {json_data["pagination"]["skip"]//100+1}")
                url = f"{API_BASE}{json_data["@odata.nextLink"]}" # Updates our URL to paginate
                time.sleep(2.5) # Pauses to ensure no timeouts happen
            else:
                match statuscode: # Handles various connection errors
                    case 401: # 401 = Missing token
                        newtoken = requests.post(f"{API_BASE}/api/auth/token", json={"email": EMAIL}) # Fetches a new token
                        if newtoken.json()["token"] != token: # Checks if the current token and the new token are identical
                            token = newtoken.json()["token"] # Saves our new token
                            logger.error("Token expired, fetching new token") # Sends info to our log                      
                            with open("SavedToken.env", "w") as SavedToken: # Saves our token in our env file
                                SavedToken.write(f"TOKEN={token}")
                            dotenv.load_dotenv("SavedToken.env") # Reloads our token
                            continue
                        else:
                            logger.warning(f"{statuscode}: Rate limit, waiting 2 minutes")
                            time.sleep(120)
                    case 418 | 503: # 418 | 503 = Rate limit, too many requests
                        logger.warning(f"{statuscode}: Rate limit, trying again")
                        time.sleep(2)
                    case _: # Handles all other errors
                        logger.error(f"Unexpected {statuscode} error, trying again")
                        TRACKER += 1
                        if TRACKER == 3: # Handles unexpected persistent errors
                            logger.critical(f"Persistent {statuscode} error, stopping program")
                            break
                        time.sleep(2)
        except KeyError: # Checks that @odata.nextLink is no longer present to stop the loop
            logger.info("All pages fetched") # Sends info to our log
            break # Stops the loop
    return allrecords

records = get_incidents() # Records is all our incidents

database = sqlite3.connect("database.db") # Connects to our database
cursor = database.cursor() # Points at our database

# Creates our incidents table
cursor.execute("""CREATE TABLE IF NOT EXISTS [.Incidents] 
(incidentId TEXT PRIMARY KEY,
incidentName TEXT NOT NULL,
severity TEXT NOT NULL,
status TEXT NOT NULL,
createdTime TEXT NOT NULL)""")

# Creates our alerts table
cursor.execute("""CREATE TABLE IF NOT EXISTS [alerts] 
(incidentId TEXT NOT NULL,
alertId TEXT PRIMARY KEY,
machineId TEXT NOT NULL,
detectionSource TEXT NOT NULL,
firstActivity TEXT NOT NULL,
FOREIGN KEY(incidentId) REFERENCES incidents (incidentId))""")

# Creates our IOCs table
cursor.execute("""CREATE TABLE IF NOT EXISTS [IOCs] 
(incidentId TEXT NOT NULL,
alertId TEXT NOT NULL,
type TEXT NOT NULL,
value TEXT,
PRIMARY KEY (alertId, type, value)
FOREIGN KEY(incidentId) REFERENCES incidents (incidentId),
FOREIGN KEY(alertId) REFERENCES alerts (alertId))""")

TOTAL_INCIDENTS = 0 # Tracks our total incidents
TOTAL_ALERTS = 0 # Tracks our total alerts

for i in range(len(records)): # Loops through all our pages
    if TOTAL_INCIDENTS > 0:
        logger.info(f"{TOTAL_INCIDENTS} new incidents added") # Tracks how many incidents are being added
    logger.info(f"Loading data from page: {i+1}/{len(records)}") # Tracks which page is currently loaded
    for p in records[i]["value"]: # Loops through the incident data
            incidentId = p.get("incidentId")
            incidentName = p.get("incidentName")
            severity = p.get("severity")
            status = p.get("status")
            createdTime = p.get("createdTime")
            
            try: # Inputs new data into our incidents table
                cursor.execute("""INSERT INTO [.Incidents] 
                (incidentId, incidentName, severity, status, createdTime) 
                values (?, ?, ?, ?, ?)""", 
                (incidentId, incidentName, severity, status, createdTime))
                TOTAL_INCIDENTS += 1 # Tracks how many new incidents have been added
            except sqlite3.IntegrityError: # Ensures existing data isn't duplicated
                pass

            for a in p["alerts"]: # Loops through the alerts data
                alertId = a.get("alertId")
                machineId = a.get("machineId")
                detectionSource = a.get("detectionSource")
                firstActivity = a.get("firstActivity")
            
                try: # Inputs new data into our alerts table
                    cursor.execute("""INSERT INTO [alerts] 
                    (incidentId, alertId, machineId, DetectionSource, firstActivity) 
                    values (?, ?, ?, ?, ?)""", 
                    (incidentId, alertId, machineId, detectionSource, firstActivity))
                    TOTAL_ALERTS += 1 # Tracks how many new alerts have been added
                except sqlite3.IntegrityError: # Ensures existing data isn't duplicated
                    pass

                """ The following 6 segments are identical, with the exception that they """
                """ handle different IOCs within the entities key inside of our data. """
                """ Only the first segment will have comments, but the notes are applicable """
                """ to all of the segments, due to them being identical in nature """

                try: domains = str(a["entities"]["domains"]) # Attempts to convert domains to a string (SQL can't handle lists)
                except KeyError: domains = None # If domains is empty, it instead turns it into a Null value 
                try: # Inputs new data into our IOCs table
                    cursor.execute("""INSERT INTO [IOCs]
                        (incidentId, alertId, type, value) 
                        values (?, ?, ?, ?)""", 
                        (incidentId, alertId, f"domains", domains))
                except sqlite3.IntegrityError: pass # Ensures existing data isn't duplicated
                    
                try: emails = str(a["entities"]["emails"])
                except KeyError: emails = "None"
                try:
                    cursor.execute("""INSERT INTO [IOCs]
                        (incidentId, alertId, type, value) 
                        values (?, ?, ?, ?)""", 
                        (incidentId, alertId, f"emails", emails))
                except sqlite3.IntegrityError: pass

                try: fileHashes = str(a["entities"]["fileHashes"])
                except KeyError: fileHashes = "None"
                try:
                    cursor.execute("""INSERT INTO [IOCs]
                        (incidentId, alertId, type, value) 
                        values (?, ?, ?, ?)""", 
                        (incidentId, alertId, f"FileHashes", fileHashes))
                except sqlite3.IntegrityError: pass

                try: ips = str(a["entities"]["ips"])
                except KeyError: ips = "None"
                try:
                    cursor.execute("""INSERT INTO [IOCs]
                        (incidentId, alertId, type, value) 
                        values (?, ?, ?, ?)""", 
                        (incidentId, alertId, f"IPs", ips))
                except sqlite3.IntegrityError: pass

                try: processes = str(a["entities"]["processes"])
                except KeyError: processes = "None"
                try:
                    cursor.execute("""INSERT INTO [IOCs]
                            (incidentId, alertId, type, value) 
                            values (?, ?, ?, ?)""", 
                            (incidentId, alertId, f"processes", processes))
                except sqlite3.IntegrityError: pass

                try: urls = str(a["entities"]["urls"])
                except KeyError: urls = "None"
                try:
                    cursor.execute("""INSERT INTO [IOCs]
                        (incidentId, alertId, type, value) 
                        values (?, ?, ?, ?)""", 
                        (incidentId, alertId, f"URLs", urls))
                except sqlite3.IntegrityError: pass
                database.commit() # Commits all our data to the database
                continue # Goes onto the next page of the dataset

logger.info(f"{TOTAL_INCIDENTS} new incidents, with {TOTAL_ALERTS} new alerts, added") # Sends info to our log
logger.info("Program finished") # Sends info to our log
database.close() # Closes our database