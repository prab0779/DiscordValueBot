import discord
from discord.ext import commands
import pandas as pd
import difflib
from discord import Embed
import re
import sqlite3
from datetime import datetime
import random
import logging
from discord.ui import Button, View
import sys
from discord.ext import tasks
from fuzzywuzzy import fuzz
import openai
from trello import TrelloClient
import requests
import os
from fuzzywuzzy import process
import os
from dotenv import load_dotenv

load_dotenv() 

sys.stdout.reconfigure(encoding='utf-8')

# Set up logging
logging.basicConfig(level=logging.INFO)

# Load the data from an Excel file
file_path = r"valuedata.xlsx"  # Ensure the file is in the correct path
data = pd.read_excel(file_path)  # Load the data into a pandas DataFrame

# Bot setup: Enabling necessary intents and configuring the bot
intents = discord.Intents.default()
intents.message_content = True  # Enable message content intent
bot = commands.Bot(command_prefix="?", intents=intents)

# Clean up column names by stripping any extra spaces
data.columns = data.columns.str.strip()

# allowed channel IDs and allowed user IDs
ALLOWED_CHANNELS = [1321941777879404646]
ALLOWED_USERS = [512671808886013962]

# Check for allowed channels – if not in an allowed channel, simply ignore the command.
def allowed_channel_silent():
    def predicate(ctx):
        if ctx.author.id in ALLOWED_USERS:
            logging.info(f"User {ctx.author} is allowed regardless of channel.")
            return True
        if ctx.channel.id in ALLOWED_CHANNELS:
            logging.info(f"Channel {ctx.channel} is allowed.")
            return True
        logging.info(f"User {ctx.author} in channel {ctx.channel} is not allowed.")
        return False
    return commands.check(predicate)

# Check for allowed users – if not allowed, send a message notifying them.
def allowed_user():
    async def predicate(ctx):
        if ctx.author.id in ALLOWED_USERS:
            return True
        else:
            await ctx.reply("⚠️ This command is restricted to allowed users.")
            return False
    return commands.check(predicate)

# Global error handler to silently ignore CheckFailure errors.
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        # The allowed_channel check returns False in disallowed channels, so ignore these errors.
        return
    raise error

# First, create database tables to store allowed users, allowed channels, and command permissions.
def init_settings_db():
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    # Table for allowed users (store user IDs)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_users (
            user_id INTEGER PRIMARY KEY
        )
    """)
    # Table for allowed channels (store channel IDs)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_channels (
            channel_id INTEGER PRIMARY KEY
        )
    """)
    # Table for command permissions (public or private)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_permissions (
            command_name TEXT PRIMARY KEY,
            permission TEXT
        )
    """)
    conn.commit()
    conn.close()

init_settings_db()

# Helper functions to load settings from the database.
def load_allowed_users():
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM allowed_users")
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def load_allowed_channels():
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT channel_id FROM allowed_channels")
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def load_command_permissions():
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT command_name, permission FROM command_permissions")
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}

# Instead of hardcoding, load them on startup.
ALLOWED_USERS = load_allowed_users() or [512671808886013962]  # Default if table empty.
ALLOWED_CHANNELS = load_allowed_channels() or [1321941777879404646]
command_permissions = load_command_permissions()  # defaults to empty dict, meaning all commands public.

# Functions to update the database for allowed users/channels and command permissions.
def add_allowed_user_db(user_id: int):
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO allowed_users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()

def remove_allowed_user_db(user_id: int):
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM allowed_users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def add_allowed_channel_db(channel_id: int):
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO allowed_channels (channel_id) VALUES (?)", (channel_id,))
    conn.commit()
    conn.close()

def remove_allowed_channel_db(channel_id: int):
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM allowed_channels WHERE channel_id = ?", (channel_id,))
    conn.commit()
    conn.close()

def set_command_permission_db(cmd_name: str, permission: str):
    conn = sqlite3.connect("settings.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO command_permissions (command_name, permission) VALUES (?, ?)", (cmd_name, permission))
    conn.commit()
    conn.close()

# Now update your mod commands to update both the global variable and the database.
@bot.command(name="add_allowed_user", aliases=["allow_user"])
@allowed_user()
@allowed_channel_silent()
async def add_allowed_user(ctx, user: discord.Member):
    """
    Add a user to the allowed users list (persisted).
    Usage: ?add_allowed_user @User
    """
    if user.id in ALLOWED_USERS:
        await ctx.reply(f"{user.mention} is already allowed.", mention_author=False)
    else:
        ALLOWED_USERS.append(user.id)
        add_allowed_user_db(user.id)
        await ctx.reply(f"{user.mention} has been added to allowed users.", mention_author=False)

@bot.command(name="remove_allowed_user", aliases=["disallow_user"])
@allowed_user()
@allowed_channel_silent()
async def remove_allowed_user(ctx, user: discord.Member):
    """
    Remove a user from the allowed users list (persisted).
    Usage: ?remove_allowed_user @User
    """
    if user.id not in ALLOWED_USERS:
        await ctx.reply(f"{user.mention} is not in the allowed users list.", mention_author=False)
    else:
        ALLOWED_USERS.remove(user.id)
        remove_allowed_user_db(user.id)
        await ctx.reply(f"{user.mention} has been removed from allowed users.", mention_author=False)

@bot.command(name="add_allowed_channel", aliases=["allow_channel"])
@allowed_user()
@allowed_channel_silent()
async def add_allowed_channel(ctx, channel: discord.TextChannel):
    """
    Add a channel to the allowed channels list (persisted).
    Usage: ?add_allowed_channel #channel-name
    """
    if channel.id in ALLOWED_CHANNELS:
        await ctx.reply(f"{channel.mention} is already allowed.", mention_author=False)
    else:
        ALLOWED_CHANNELS.append(channel.id)
        add_allowed_channel_db(channel.id)
        await ctx.reply(f"{channel.mention} has been added to allowed channels.", mention_author=False)

@bot.command(name="remove_allowed_channel", aliases=["disallow_channel"])
@allowed_user()
@allowed_channel_silent()
async def remove_allowed_channel(ctx, channel: discord.TextChannel):
    """
    Remove a channel from the allowed channels list (persisted).
    Usage: ?remove_allowed_channel #channel-name
    """
    if channel.id not in ALLOWED_CHANNELS:
        await ctx.reply(f"{channel.mention} is not in the allowed channels list.", mention_author=False)
    else:
        ALLOWED_CHANNELS.remove(channel.id)
        remove_allowed_channel_db(channel.id)
        await ctx.reply(f"{channel.mention} has been removed from allowed channels.", mention_author=False)

@bot.command(name="public")
@allowed_user()
@allowed_channel_silent()
async def set_public(ctx, cmd_name: str):
    """
    Set a command to public (available to everyone).
    Usage: ?public <command name>
    """
    cmd = bot.get_command(cmd_name)
    if not cmd:
        await ctx.reply(f"Command '{cmd_name}' not found.", mention_author=False)
        return
    command_permissions[cmd.name] = "public"
    set_command_permission_db(cmd.name, "public")
    await ctx.reply(f"Command '{cmd.name}' is now PUBLIC.", mention_author=False)

@bot.command(name="private")
@allowed_user()
@allowed_channel_silent()
async def set_private(ctx, cmd_name: str):
    """
    Set a command to private (restricted to allowed users).
    Usage: ?private <command name>
    """
    cmd = bot.get_command(cmd_name)
    if not cmd:
        await ctx.reply(f"Command '{cmd_name}' not found.", mention_author=False)
        return
    command_permissions[cmd.name] = "private"
    set_command_permission_db(cmd.name, "private")
    await ctx.reply(f"Command '{cmd.name}' is now PRIVATE.", mention_author=False)

# Global dictionary to track command access; default is "public"
command_permissions = {}

# Global check to enforce access settings on commands
@bot.before_invoke
async def check_command_access(ctx):
    cmd_name = ctx.command.name
    # If the command is set to private and the user is not allowed, block it.
    if command_permissions.get(cmd_name, "public") == "private":
        if ctx.author.id not in ALLOWED_USERS:
            await ctx.reply("This command is private.", mention_author=False)
            raise commands.CheckFailure("Command is private")

# Global list to store error logs
ERROR_LOGS = []

# Global flag for maintenance mode
maintenance_mode = False

# Before invoking any command, check if maintenance mode is active.
@bot.before_invoke
async def check_maintenance(ctx):
    # List of commands that are allowed during maintenance mode
    mod_commands = ["modmenu", "maintenance", "errorlogs", "help", "vouch", "myvouches", "vouchleaderboard"]
    if maintenance_mode and ctx.command.name not in mod_commands:
        await ctx.reply("Bot is in maintenance mode. Public commands are temporarily disabled.", mention_author=False)
        raise commands.CheckFailure("Maintenance mode active")

# Global error handler that stores errors in ERROR_LOGS
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        return  # Skip logging check failures
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {ctx.command} - {error}"
    ERROR_LOGS.append(log_entry)
    logging.error(log_entry)
    raise error

# Command to display recent error logs (last 10 errors)
@bot.command(name="errorlogs", aliases=["elog"])
@allowed_user()
@allowed_channel_silent()
async def error_logs(ctx):
    """
    Display the recent error logs.
    """
    if not ERROR_LOGS:
        await ctx.reply("No error logs recorded.", mention_author=False)
        return
    logs = "\n".join(ERROR_LOGS[-10:])  # Display the last 10 errors
    await ctx.reply(f"Recent Error Logs:\n```\n{logs}\n```", mention_author=False)

# Command to toggle maintenance mode
@bot.command(name="maintenance", aliases=["maint"])
@allowed_user()
@allowed_channel_silent()
async def maintenance(ctx, mode: str = None):
    """
    Toggle maintenance mode.
    Usage: !maintenance on/off
    When enabled, public commands are disabled.
    """
    global maintenance_mode
    if mode is None:
        await ctx.reply(f"Maintenance mode is currently {'enabled' if maintenance_mode else 'disabled'}.", mention_author=False)
        return
    if mode.lower() == "on":
        maintenance_mode = True
        await ctx.reply("Maintenance mode enabled. Public commands are now disabled.", mention_author=False)
    elif mode.lower() == "off":
        maintenance_mode = False
        await ctx.reply("Maintenance mode disabled. Public commands are now enabled.", mention_author=False)
    else:
        await ctx.reply("Invalid mode! Use 'on' or 'off'.", mention_author=False)

@bot.command(name="update_item", aliases=["ui"])
@allowed_user()
@allowed_channel_silent()
async def update_item(ctx, item_identifier: str, new_value: float, new_demand: float, new_rate: float):
    """
    Update an item's Value, Demand (out of 10), and Rate of Change.
    Accepts either an item name or its emoji.
    Usage: ?update_item <item_identifier> <new_value> <new_demand> <new_rate>
    Example: ?update_item <:frost:1310042922737078373> 1200 8 0.05
    """
    global data, file_path  # Uses global DataFrame and Excel file path
    # Convert emoji to item name if applicable, then normalize the text.
    item_identifier = replace_emojis_with_items(item_identifier).strip().lower()
    item_found = False

    for idx, row in data.iterrows():
        if row["Item name"].strip().lower() == item_identifier:
            data.at[idx, "Value"] = new_value
            data.at[idx, "Demand (out of 10)"] = new_demand
            if "rate of change" in data.columns:
                data.at[idx, "rate of change"] = new_rate
            else:
                data["rate of change"] = new_rate
            item_found = True
            break

    if not item_found:
        await ctx.reply(f"Item '{item_identifier}' not found.", mention_author=False)
        return

    try:
        data.to_excel(file_path, index=False)
        # For confirmation, convert the updated item name back into emoji using robust replacement.
        confirmation = f"Updated **{robust_replace_item_names_with_emojis(item_identifier)}**:\n" \
                       f"**Value:** {new_value}\n" \
                       f"**Demand:** {new_demand}/10\n" \
                       f"**Rate of Change:** {new_rate}"
        await ctx.reply(confirmation, mention_author=False)
    except Exception as e:
        await ctx.reply(f"Error updating item: {e}", mention_author=False)

@bot.command(name="modmenu", aliases=["mm"])
@allowed_channel_silent()
@allowed_user()
async def mod_menu(ctx):
    """
    Display a mod menu with a list of available mod/admin commands in two parts.
    """
    # First half of commands
    embed1 = discord.Embed(
        title="🛠️ Mod/Admin Menu (Part 1)",
        description="Here's a list of mod/admin commands:",
        color=discord.Color.purple()
    )
    embed1.add_field(
        name="?value or ?v [emojis]",
        value="Retrieve value, demand, and rate of change for one or more items.",
        inline=False
    )
    embed1.add_field(
        name="?compare or ?c [my_items] :for: [their_items]",
        value="Compare two trades and show detailed breakdowns and percentage differences.",
        inline=False
    )
    embed1.add_field(
        name="?history or ?hs [my_items] :for: [their_items]",
        value="Record a trade in the history database with detailed values.",
        inline=False
    )
    embed1.add_field(
        name="?myhistory or ?mh",
        value="Display your recent trade history with summaries and insights.",
        inline=False
    )
    embed1.add_field(
        name="?suggest or ?st [offered item]",
        value="Suggest trades based on historical data.",
        inline=False
    )
    embed1.add_field(
        name="?value_suggest or ?vs [item name]",
        value="Suggest items with similar values using a value system formula.",
        inline=False
    )
    embed1.add_field(
        name="?trends or ?tt",
        value="Show trade trends like top trades and overpaid/underpaid trades.",
        inline=False
    )
    embed1.add_field(
        name="?vouch [@User] [reason]",
        value="Vouch for a user with an optional reason.",
        inline=False
    )
    embed1.add_field(
        name="?public <command>",
        value="Set a command to public (available to everyone).",
        inline=False
    )
    embed1.add_field(
        name="?private <command>",
        value="Set a command to private (restricted to allowed users).",
        inline=False
    )
    embed1.set_footer(text="Part 1/2 - Use ?modmenu for full list.")

    # Second half of commands
    embed2 = discord.Embed(
        title="🛠️ Mod/Admin Menu (Part 2)",
        description="Additional mod/admin commands:",
        color=discord.Color.purple()
    )
    embed2.add_field(
        name="?myvouches",
        value="View your own vouches and recent logs.",
        inline=False
    )
    embed2.add_field(
        name="?vouches [@User]",
        value="View another user's vouches and recent logs.",
        inline=False
    )
    embed2.add_field(
        name="?vouchleaderboard or ?vouchlb",
        value="See the top 5 most vouched users.",
        inline=False
    )
    embed2.add_field(
        name="?challenge or ?tc",
        value="Generate a random trade challenge for voting.",
        inline=False
    )
    embed2.add_field(
        name="?w and ?l",
        value="Vote Win or Loss on a trade challenge.",
        inline=False
    )
    embed2.add_field(
        name="?clearhistory or ?ch",
        value="Clear your trade history from the database.",
        inline=False
    )
    embed2.add_field(
        name="?print_sheet or ?ps",
        value="Print the contents of the Excel sheet to the console.",
        inline=False
    )
    embed2.add_field(
        name="?emoji_list",
        value="List all custom emojis available in the server.",
        inline=False
    )
    embed2.add_field(
        name="?ask or ?a [query]",
        value="Ask a query about the game and get an AI-generated answer.",
        inline=False
    )
    embed2.add_field(
        name="?trello",
        value="Get the link to the Trello board with detailed game information.",
        inline=False
    )
    embed2.add_field(
        name="?errorlogs or ?elog",
        value="Show the last 10 error log entries for diagnosing issues.",
        inline=False
    )
    embed2.add_field(
        name="?maintenance or ?maint [on/off]",
        value="Toggle maintenance mode. When enabled, public commands are disabled.",
        inline=False
    )
    embed2.add_field(
        name="?add_allowed_user or ?allow_user @User",
        value="Add a user to the allowed users list (persisted).",
        inline=False
    )
    embed2.add_field(
        name="?remove_allowed_user or ?disallow_user @User",
        value="Remove a user from the allowed users list (persisted).",
        inline=False
    )
    embed2.add_field(
        name="?add_allowed_channel or ?allow_channel #channel",
        value="Add a channel to the allowed channels list (persisted).",
        inline=False
    )
    embed2.add_field(
        name="?remove_allowed_channel or ?disallow_channel #channel",
        value="Remove a channel from the allowed channels list (persisted).",
        inline=False
    )
    embed2.add_field(
        name="?update_item or ?ui <item> <new_value> <new_demand> <new_rate>",
        value="Update an item's Value, Demand, and Rate of Change. Accepts an item name or emoji.",
        inline=False
    )
    embed2.add_field(
        name="?modmenu or ?mm",
        value="Display this mod/admin command menu.",
        inline=False
    )
    embed2.set_footer(text="Part 2/2 - Use ?modmenu for full list.")

    await ctx.reply(embed=embed1, mention_author=False)
    await ctx.send(embed=embed2)

@bot.command(name="detect_changes", aliases=["changes", "dc"])
@allowed_user()
@allowed_channel_silent()
async def detect_changes(ctx):
    """
    Detect changes in values between old and new Excel files and notify in a specified Discord channel.
    """
    try:
        # File paths for old and new data
        old_file_path = r"valuedata.xlsx"  
        new_file_path = r"valuedata.xlsx"  

        # Load old and new data
        old_data = pd.read_excel(old_file_path)
        new_data = pd.read_excel(new_file_path)

        # Ensure column names are consistent and stripped of extra spaces
        old_data["Item name"] = old_data["Item name"].astype(str)
        new_data["Item name"] = new_data["Item name"].astype(str)

        # Define the function to detect changes
        def detect_changes_fixed(old_data, new_data):
            """
            Detect changes in values between old and new data, with improved handling for NaN values.
            """
            required_columns = {"Item name", "Value"}
            if not required_columns.issubset(old_data.columns) or not required_columns.issubset(new_data.columns):
                raise ValueError("Both datasets must contain 'Item name' and 'Value' columns.")

            old_data["Value"] = pd.to_numeric(old_data["Value"], errors="coerce")
            new_data["Value"] = pd.to_numeric(new_data["Value"], errors="coerce")

            merged_data = pd.merge(
                old_data, new_data, on="Item name", suffixes=("_old", "_new"), how="inner"
            )
            merged_data = merged_data.dropna(subset=["Value_old", "Value_new"])

            changes = {"increased": [], "decreased": []}
            for _, row in merged_data.iterrows():
                old_value = row["Value_old"]
                new_value = row["Value_new"]
                item_name = row["Item name"]

                if old_value != new_value:
                    percentage_change = ((new_value - old_value) / old_value) * 100 if old_value != 0 else float("inf")
                    direction = "increased" if new_value > old_value else "decreased"
                    changes[direction].append({
                        "item": item_name,
                        "old_value": old_value,
                        "new_value": new_value,
                        "change": round(percentage_change, 2),
                    })
            return changes

        # Detect changes
        changes_detected = detect_changes_fixed(old_data, new_data)

        # Send updates to the specified channel
        UPDATE_CHANNEL_ID = 1321941777879404646
        update_channel = bot.get_channel(UPDATE_CHANNEL_ID)

        if not update_channel:
            await ctx.reply("⚠️ Could not find the update channel.", mention_author=False)
            return

        if changes_detected["increased"] or changes_detected["decreased"]:
            embed = discord.Embed(
                title="🔔 Value Changes Detected!",
                color=discord.Color.gold()
            )

            if changes_detected["increased"]:
                embed.add_field(
                    name="⬆️ Increased Items",
                    value="\n".join([
                        f"**{change['item']}**\n"
                        f"• Old Value: `{change['old_value']}`\n"
                        f"• New Value: `{change['new_value']}`\n"
                        f"• Change: `{change['change']}%` ⬆️ Increased"
                        for change in changes_detected["increased"]
                    ]),
                    inline=False
                )

            if changes_detected["decreased"]:
                embed.add_field(
                    name="⬇️ Decreased Items",
                    value="\n".join([
                        f"**{change['item']}**\n"
                        f"• Old Value: `{change['old_value']}`\n"
                        f"• New Value: `{change['new_value']}`\n"
                        f"• Change: `{change['change']}%` ⬇️ Decreased"
                        for change in changes_detected["decreased"]
                    ]),
                    inline=False
                )

            await update_channel.send(embed=embed)
            await ctx.reply(f"✅ Changes have been sent to the updates channel: <#{UPDATE_CHANNEL_ID}>.", mention_author=False)
        else:
            await ctx.reply("No changes detected between the files.", mention_author=False)

    except Exception as e:
        print(f"Error detecting changes: {e}")
        await ctx.reply(f"⚠️ Error detecting changes: {e}", mention_author=False)

@bot.command(name="print_sheet", aliases=["ps"])
@allowed_user()
@allowed_channel_silent()
async def print_sheet(ctx):
    """
    Print the contents of the Excel sheet to the Visual Studio console.
    """
    try:
        # Load the data from the Excel file
        file_path = r"valuedata.xlsx"  
        df = pd.read_excel(file_path)

        # Convert the DataFrame to a string and print it
        print("Excel Sheet Contents:")
        print(df.to_string(index=False))  # Print without the index column
        await ctx.reply("Excel sheet printed to the console.", mention_author=False)

    except Exception as e:
        # Handle any errors during loading or output
        print(f"Error loading Excel sheet: {e}")
        await ctx.reply(f"⚠️ Error loading Excel sheet: {e}", mention_author=False)

def enhanced_find_item(data, item_name, case_sensitive=True):
    """
    Search for an item in the dataset, returning details or similar suggestions.
    """
    # Adjust case sensitivity
    item_name = item_name if case_sensitive else item_name.lower()
    data['Item name'] = data['Item name'].str.lower(
    ) if not case_sensitive else data['Item name']

    # Try exact match first
    exact_match = data[data['Item name'] == item_name]
    if not exact_match.empty:
        row = exact_match.iloc[0]
        return {
            "Item name": row['Item name'],
            "Demand": row['Demand (out of 10)'],
            "Value": row['Value'],
            "Rate of Change":
            row.get('rate of change',
                    'N/A')  # Handle missing columns gracefully
        }

    # Broad search with 'contains' for partial matches
    contains_match = data[data['Item name'].str.contains(item_name, na=False)]
    if not contains_match.empty:
        row = contains_match.iloc[0]
        return {
            "Item name": row['Item name'],
            "Demand": row['Demand (out of 10)'],
            "Value": row['Value'],
            "Rate of Change": row.get('rate of change', 'N/A')
        }

    # Fuzzy matching for suggestions
    item_names = data['Item name'].tolist()
    suggestions = difflib.get_close_matches(item_name,
                                            item_names,
                                            n=5,
                                            cutoff=0.5)
    if suggestions:
        return {"Suggestions": suggestions}

    # If no matches or suggestions are found
    return None

# Utility function: Find an exact or closest match using fuzzy matching
def find_exact_or_closest(item_name):
    """
    Search for the item in the Excel sheet by exact match or closest match.
    Assumes 'data' is a DataFrame containing item data.
    """
    # Remove emojis and extra spaces from item names
    sanitized_name = re.sub(r"<:[^:]+:[0-9]+>", "", item_name).strip()

    # Ensure 'data' exists and contains the necessary columns
    if 'Item name' not in data.columns or 'Value' not in data.columns:
        return None

    # Try to find an exact match
    match = data[data['Item name'].str.casefold() == sanitized_name.casefold()]
    if not match.empty:
        return match.iloc[0]

    # Fallback: Find closest match (case-insensitive substring match)
    closest_match = data[data['Item name'].str.contains(sanitized_name,
                                                        case=False)]
    if not closest_match.empty:
        return closest_match.iloc[0]

    # If no match is found, return None
    return None

# Command: Show top X items based on a specific criterion (demand or value)
@bot.command(name="top", aliases=["t"])
@allowed_user()
@allowed_channel_silent()
async def top_items(ctx, number: int = 5, *, criterion: str = "demand"):
    criterion = criterion.lower()
    # Log the command usage
    print(
        f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}"
    )
    if criterion not in ["demand", "value"]:
        await ctx.reply("Invalid criterion! Use `demand` or `value`.",
                        mention_author=False)
        return
    try:
        # Convert the relevant column to numeric and drop invalid entries
        column_name = "Demand (out of 10)" if criterion == "demand" else "Value"
        data[column_name] = pd.to_numeric(data[column_name], errors='coerce')
        sorted_data = data.dropna(subset=[column_name]).sort_values(
            by=column_name, ascending=False).head(number)

        if sorted_data.empty:
            await ctx.reply(
                f"No items found for the specified criterion: {criterion}.",
                mention_author=False)
            return

        # Create an embed to format the response
        embed = discord.Embed(
            title=f"Top {number} Items by {criterion.capitalize()}",
            description=
            f"Here are the top {number} items sorted by {criterion}.",
            color=discord.Color.blue())

        # Add each item as a field in the embed
        for index, (_, row) in enumerate(sorted_data.iterrows(), start=1):
            embed.add_field(
                name=f"{index}. {row['Item name']}",
                value=f"**{criterion.capitalize()}**: {row[column_name]}",
                inline=False)

        # Send the embed as a reply to the user
        await ctx.reply(embed=embed, mention_author=False)

    except Exception as e:
        await ctx.reply(
            "An error occurred while fetching the top items. Please try again later.",
            mention_author=False)
        print(e)

# Command: Filter items based on a given condition (supports Python-like syntax)
@bot.command(name="filter", aliases=["f"])
@allowed_user()
@allowed_channel_silent()
async def filter_items(ctx, *, condition: str):
    try:
        # Map shorthand names to actual column names
        column_aliases = {
            "demand": "Demand (out of 10)",
            "value": "Value",
            "rate_of_change": "rate of change"
        }
        # Replace shorthand with actual column names
        for alias, actual_name in column_aliases.items():
            condition = condition.replace(alias, f"`{actual_name}`")

        # Ensure columns are numeric
        for column in ["Demand (out of 10)", "Value", "rate of change"]:
            if column in data.columns:
                data[column] = pd.to_numeric(data[column], errors='coerce')

        # Apply the query
        filtered_data = data.query(condition)

        if filtered_data.empty:
            await ctx.reply("No items match the given filter criteria.",
                            mention_author=False)
            return

        # Format and send results
        embed = discord.Embed(
            title="Filtered Items",
            description=f"Items matching the filter: `{condition}`",
            color=discord.Color.green())

        for _, row in filtered_data.head(10).iterrows():
            embed.add_field(
                name=row["Item name"],
                value=
                f"**Demand**: {row['Demand (out of 10)']}\n**Value**: {row['Value']}",
                inline=False)

        if len(filtered_data) > 10:
            embed.set_footer(
                text=
                "Showing the first 10 results. Refine your filter for more specific results."
            )
        await ctx.reply(embed=embed, mention_author=False)

    except Exception as e:
        await ctx.reply(
            "Invalid filter criteria. Use Python-like syntax, e.g., `demand > 8`.",
            mention_author=False)
        print(f"Error: {e}")

@bot.command(name="emoji_list")
@allowed_user()
@allowed_channel_silent()
async def emoji_list(ctx):
    emojis = ctx.guild.emojis  # Get all emojis in the server
    emoji_list_text = "\n".join([f"{emoji} → `{emoji}`" for emoji in emojis])
    full_message = f"Here are the server's custom emojis:\n{emoji_list_text}"
    chunk_size = 1900  # Use a chunk size slightly less than 2000 to allow for any extra characters
    
    # Split and send each chunk
    for i in range(0, len(full_message), chunk_size):
        await ctx.send(full_message[i:i + chunk_size])

def replace_with_emojis(trade_details):
    logging.debug(f"Original trade details: {trade_details}")
    # Replace item names with their corresponding emojis from the emoji_to_item map
    for item, emoji in emoji_to_item.items():
        if item.lower() in trade_details.lower():  # Case-insensitive matching
            logging.debug(f"Replacing '{item}' with '{emoji}'")
            trade_details = trade_details.replace(item, emoji)
        else:
            logging.debug(f"Skipping '{item}' as it is not in the trade details.")
    logging.debug(f"Replaced trade details: {trade_details}")
    return trade_details

def find_suggested_trades(value):
    """
    Finds items with values close to the provided value.
    For now, it will return items with a value within a certain range.
    """
    # Define the acceptable value range for suggested trades (adjust as necessary)
    value_range = 5  # Example: find items within a range of 5 units of the target value

    suggested_trades = []

    # Loop through the items and find those with values within the specified range
    for item in data:  # Assuming 'data' contains all the items' details
        item_value = item[
            'Value']  # Ensure 'Value' is the correct key for item value in your data
        if abs(item_value - value) <= value_range:
            suggested_trades.append(item)

    return suggested_trades

def replace_emojis_with_items(text: str) -> str:
    """
    Replaces emojis in the input text with their corresponding item names.
    """
    for emoji, item_name in emoji_to_item.items():
        if emoji in text:
            text = text.replace(emoji, item_name)
    return text

# Command: Compare two items side by side (supports emojis as input)
# Helper functions and parse_items function should be defined before any command that uses them
emoji_to_item = {
        "<:for:1311162334839832668>": "with",
        "<:angelscythe:1340312208969568318>": "angelscythe",
        "<:beerusscythe:1340312228569550868>": "beerusscythe",
        "<:beowolfgloves:1311752799985467392>": "beowolfgloves",
        "<:blackcatrinhat:1310043726780956704>": "blackcatrinhat",
        "<:blackcatrinset:1310043282734190693>": "blackcatrinset",
        "<:broloearrings:1310043329420984320>": "broloearrings",
        "<:lighttunnelmask:1310041821136556072>": "lighttunnelmask",
        "<:demonmark:1310041182453370990>": "majinmark",
        "<:santahat:1310040524283056158>": "santahat",
        "<:senzubean:1311751797450211368>": "senzubean",
        "<:swordofhopesoul:1310042139811643463>": "swordofhope",
        "<:trollfacemask:1310040334658568203>": "trollfacemask",
        "<:voidscythe:1340312184890064956>": "voidscythe",
        "<:whitecatrinhat:1310041902678020096>": "whitecatrinhat",
        "<:whitecatrinset:1310043188349636669>": "whitecatrinsetwithhat",
        "<:whitepumpkin2023:1310039452030074890>": "whitepumpkinhead",
        "<:BrolyZset:1310043690965930064>": "brolyzset",
        "<:dsjacket:1309947700413993082>": "dsjacket",
        "<:halflaset:1310042381378257036>": "halflaset",
        "<:opamancape:1310041141147598859>": "opamancape",
        "<:beerussoul:1310042878885629993>": "beerussoul",
        "<:BrolySaura:1311751790584397929>": "brolysaura",
        "<:BrolyZaura:1311751792912240720>": "brolyzaura",
        "<:cellaura:1310043101657698444>": "cellaura",
        "<:21aura:1310043771379126293>": "demon21aura",
        "<:despairsoul:1309978206463590420>": "despairsoul",
        "<:easteraura:1310042997236174878>": "easteraura",
        "<:exilesoul:1310043040102223892>": "exilesoul",
        "<:festiveaura:1310042957969227916>": "festivalaura",
        "<:frost:1310042922737078373>": "frostaura",
        "<:grandmasteraura:1310040611059142697>": "grandmasteraura",
        "<:halloweenaura2023:1310042323693862972>": "halloweenaura2023",
        "<:halloweenaura2024:1310042271999066122>": "halloweenaura2024",
        "<:halloweenhalo:1310041989303111680>": "halloweenhalo",
        "<:headlessaura:1310042193838342184>": "headlessaura",
        "<:Kaleaura:1311752831430295573>": "kaleaura",
        "<:legendarypermastone:1311751795412045865>": "legpermstone",
        "<:lifesoul:1310040385711767583>": "lifesoul",
        "<:conquerorsoul:1310042030973649037>": "permconqueror",
        "<:permadespairsoul:1309977040702931065>": "permdespairsoul",
        "<:ultrainstinktaura:1310039517297639434>": "uiaura",
        "<:permabeerussoul:1310042085943935066>": "permbeerussoul",
        "<:permaexilesoul:1310041011623428156>": "permaexilesoul",
        "<:permalifesoul:1310040659369001041>": "permalifesoul",
        "<:permasaviorsoul:1309976592004419705>": "permsavior",
        "<:permasohsoul:1310040708681568299>": "permasoh",
        "<:saviorsoul:1309974884465508374>": "saviorsoul",
        "<:shadowaura:1310040483736588400>": "shadowaura",
        "<:shenronaura:1310040439360983102>": "shenronaura",
        "<:SD3:1311699819898732554>": "SD3",
        "<:SD4:1311699829629386856>": "SD4",
        "<:SD5:1311699859824185355>": "SD5",
        "<:permaconfidentsoul:1340080901857476658>": "permaconfidentsoul",
        "<:permabeastsoul:1340078462253137961>": "permabeastsoul",
        "<:zenkaipermastone:1311751798930804897>": "zenkaipermstone",
        "<:confidentsoul:1321953139406147686>": "confidentsoul",
        "<:beastsoul:1340078524463321158>": "beastsoul",
        "<:neonhalo:1340078884875669635>": "halloweenhalo",
        "<:xenogokuset:1321954023561101445>": "xenogokuset",
        "<:18earrings:1340367134840328272>": "18earings"
    }

item_to_emoji = {value: key for key, value in emoji_to_item.items()}

def robust_replace_item_names_with_emojis(text: str) -> str:
    """
    Replace full item names with their corresponding emojis using regex word boundaries,
    preventing partial replacements or strange substrings.
    """
    # Sort by length descending to avoid partial matches (e.g., "perm" vs. "permabeerussoul")
    sorted_item_names = sorted(item_to_emoji.keys(), key=len, reverse=True)
    for item_name in sorted_item_names:
        emoji = item_to_emoji[item_name]
        # Use a case-insensitive pattern with word boundaries (\b)
        pattern = rf"\b{re.escape(item_name)}\b"
        text = re.sub(pattern, emoji, text, flags=re.IGNORECASE)
    return text

def parse_items(trade_str):
    """
    Parses a trade string into a list of (item_name, quantity) tuples.
    Handles emoji-based items and text items with quantities (xN).
    """
    tokens = trade_str.split()
    parsed_items = []
    i = 0

    while i < len(tokens):
        token = tokens[i]

        # Check if the token is an emoji or text-based item
        item_name = emoji_to_item.get(token,
                                      token)  # Map emoji to name or keep text

        # Look ahead to check for quantity (xN)
        if i + 1 < len(tokens) and tokens[i + 1].startswith('x') and tokens[
                i + 1][1:].isdigit():
            quantity = int(tokens[i + 1][1:])  # Extract quantity
            i += 2  # Move past both the item and the quantity
        else:
            quantity = 1
            i += 1  # Move past the item only

        parsed_items.append((item_name, quantity))

    # Combine quantities of duplicate items
    combined_items = {}
    for item, qty in parsed_items:
        if item in combined_items:
            combined_items[item] += qty
        else:
            combined_items[item] = qty

    return list(combined_items.items())

def calculate_trade_details(trade):
    """
    Calculates the total value of a trade and prepares a detailed breakdown.
    """
    total_value = 0
    item_details = []

    for item_name, quantity in trade:
        # Replace with your item lookup function
        item_data = find_exact_or_closest(item_name)
        emoji = item_to_emoji.get(item_name,
                                  item_name)  # Use emoji if available

        if item_data is not None and not item_data.empty:  # Check if the item data is valid
            try:
                # Safely convert the value to an integer
                item_value = int(item_data['Value'])
            except (ValueError,
                    TypeError):  # Handle cases where the value is invalid
                item_value = 0  # Default to 0 if the value is not numeric

            total_item_value = item_value * quantity
            total_value += total_item_value

            item_details.append(
                f"{emoji} x{quantity} (**{item_value}** each) = **{total_item_value}**"
            )
        else:
            # Handle cases where the item is not found
            item_details.append(f"{emoji} x{quantity} (**Value not found**)")

    return total_value, "\n".join(item_details)

# Now, you can safely call parse_items in your compare command
@bot.command(name="compare", aliases=["c"])  #good not need for imporvement
@allowed_channel_silent()
async def compare(ctx, *, trade_details: str = None):
    """
    Compare trades and provide a detailed summary including total values,
    comparison results, and percentage difference. Supports multiple items.
    """
    logging.info(
        f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}"
    )
    if not trade_details:
        await ctx.send(
            "Please provide trade details in this format:\n\n"
            "!c my_items (in emoji) <:for:1311162334839832668> their_items (in emoji)"
        )
        return

    # Replace emojis in the trade details with their mapped names
    for emoji, name in emoji_to_item.items():
        trade_details = trade_details.replace(emoji, name)

    # Ensure the separator "with" exists in the input
    if " with " not in trade_details:
        await ctx.send(
            "Please provide trade details in this format:\n\n"
            "?c my_items (in emoji) <:for:1311162334839832668> their_items (in emoji)"
        )
        return

    # Split the input into "my trade" and "their trade"
    try:
        my_trade_str, their_trade_str = map(str.strip,
                                            trade_details.split(" with "))
    except ValueError:
        await ctx.send(
            "Error parsing trade details. Ensure the format is correct.")
        return

    # Parse items for both trades
    my_trade = parse_items(my_trade_str)
    their_trade = parse_items(their_trade_str)

    # Calculate trade values
    my_trade_value, my_trade_details = calculate_trade_details(my_trade)
    their_trade_value, their_trade_details = calculate_trade_details(
        their_trade)

    # Determine result and percentage difference
    if my_trade_value == their_trade_value:
        result = "Fair Trade!"
        color = discord.Color.yellow()
        percentage_difference = 0
    elif my_trade_value > their_trade_value:
        result = "L, you are overpaying!"
        color = discord.Color.red()
        percentage_difference = round(
            ((my_trade_value - their_trade_value) / their_trade_value) * 100,
            2)  # Difference relative to the smaller value
    else:
        result = "W, they are overpaying!"
        color = discord.Color.green()
        percentage_difference = round(
            ((their_trade_value - my_trade_value) / my_trade_value) * 100,
            2)  # Difference relative to the smaller value

    # Create embed
    embed = discord.Embed(title="Trade Comparison", color=color)
    embed.add_field(name="Your Trade",
                    value=f"**Items:**\n{my_trade_details}\n\n"
                    f"**Total Value**: {my_trade_value}",
                    inline=False)

    embed.add_field(name="Their Trade",
                    value=f"**Items:**\n{their_trade_details}\n\n"
                    f"**Total Value**: {their_trade_value}",
                    inline=False)

    embed.add_field(name="Result", value=f"**{result}**", inline=False)

    embed.add_field(name="Percentage Difference",
                    value=f"**{percentage_difference}%**",
                    inline=False)

    embed.set_footer(text="Contact @helper for more info.")

    # Send the embed
    await ctx.reply(embed=embed)

# Custom Help Command: Displays the list of available bot commands
bot.remove_command(
    "help")  # Remove the default help command to replace with a custom one

@bot.command(name="help", aliases=["h", "menu", "guide"])
@allowed_channel_silent()
async def custom_help(ctx):
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")

    # Create an embed to format the help text
    embed = discord.Embed(
        title="📜 Help Menu",
        description=
        "Explore all the commands available to enhance your trading experience!",
        color=discord.Color.green(),
    )

    # Add categories of commands with their respective descriptions
    embed.add_field(
        name="🔍 **Value and Item Details**",
        value=
        ("`?value` or `?v [emojis]`\n"
         "Get details like demand, value, and rate of change for one or more items.\n\n"
         "`?compare` or `?c [my_items] :for: [their_items]`\n"
         "Compare the value of two trades.\n\n"),
        inline=False,
    )

    #embed.add_field(
     #   name="📈 **Trade Analysis**",
      #  value=
       # ("`?history` or `?hs [my_items] :for: [their_items]`\n"
        # "Record a trade with values for your items and theirs.\n\n"
         #"`?myhistory` or `!mh`\n"
         #"View your trade history with summaries and insights.\n\n"
         #"`?trends` or `?tt`\n"
         #"See trends like the most common trades and overpaid/underpaid trades.\n\n"
         #"`?suggest` or `?st [offered item]`\n"
         #"Suggest trades based on community trade data.\n\n"
         #"`?value_suggest` or `?vs [item name]`\n"
         #"Suggest trades for an item using the value system."),
        #inline=False,
    #)

    embed.add_field(
        name="❓ **General Commands**",
        value=
        ("`?help` or `?h` or `?menu`\n"
         "Display this help menu.\n\n"
         "*Pro Tip:* Use command aliases for faster access, e.g., `?v` for `?value`."
         ),
        inline=False,
    )

    # Add a footer for additional information
    embed.set_footer(
        text=
        "Use commands wisely and enjoy trading! For further assistance, contact @helper."
    )

    # Send the embed as a reply
    await ctx.reply(embed=embed, mention_author=False)

# Command: Get value, demand, and rate of change for a specific item
@bot.command(name="value", aliases=["v"])
@allowed_channel_silent()
async def value(ctx, *, item_names: str = None):
    """
    Retrieve values for one or more items and present them in a visually appealing format.
    """
    logging.info(
        f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}"
    )

    if not item_names:  # Check if any items were provided
        await ctx.reply(
            "Please provide up to **3** item names or emojis separated by spaces or commas. "
            "Example: `?v <:item1:1234>, <:item2:5678>`",
            mention_author=False,
        )
        return

    # Split input by spaces, commas, or both
    items = re.split(r"[,\s]+", item_names.strip())

    # Check if the user provided more than 3 items
    over_limit = len(items) > 3
    items = items[:3]  # Limit to the first 3 items

    embed = discord.Embed(
        title="📜 Item Details",
        description="Here are the details for the requested items:",
        color=discord.Color.blue(),
    )

    for item in items:
        if not item:  # Skip empty items
            continue

        # Convert emoji to corresponding item name
        item_name = emoji_to_item.get(item, item)

        try:
            item_name = str(item_name)
            result = enhanced_find_item(data, item_name, case_sensitive=False)

            if "Item not found" in result:
                embed.add_field(
                    name=f"❌ {item}",
                    value=f"Could not find details for `{item_name}`.",
                    inline=False,
                )
            else:
                exact_match = find_exact_or_closest(item_name)
                if exact_match is None:
                    embed.add_field(
                        name=f"❌ {item}",
                        value=f"No exact match found for `{item_name}`.",
                        inline=False,
                    )
                else:
                    item_emoji = next(
                        (emoji for emoji, name in emoji_to_item.items()
                         if name.lower() == exact_match['Item name'].lower()),
                        None)
                    item_display = item_emoji if item_emoji else exact_match[
                        'Item name']

                    embed.add_field(
                        name=f"🔹 {item_display}",
                        value=(
                            f"**🔸 Demand:** {exact_match['Demand (out of 10)']}/10\n"
                            f"**💰 Value:** {exact_match['Value']}\n"
                            f"**📈 Rate of Change:** {exact_match['rate of change']}\n"
                            "\u200b"
                        ),
                        inline=False,
                    )
        except Exception as e:
            logging.error(f"Error finding item '{item}': {e}")
            embed.add_field(
                name=f"Error with {item}",
                value="An unexpected error occurred while processing this item.",
                inline=False,
            )

    # Set the appropriate footer based on the number of items processed
    if over_limit:
        embed.set_footer(text="⚠️ Only the first 3 items were processed.")
    else:
        embed.set_footer(text="Use the !compare command to analyze item trades!")

    await ctx.reply(embed=embed, mention_author=False)

@bot.command(name="spin", aliases=["s"])
@allowed_user()
@allowed_channel_silent()
async def spin(ctx, spins: int = 1):
    """
    Spin to roll for Dragon Souls with specified probabilities, supporting multiple spins.
    """
    logging.info(
        f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}"
    )
    # Define the Dragon Souls and their probabilities
    dragon_souls = [
        ("🔴Destruction Soul", 0.00000001),
        ("🔴Savior Soul", 0.14),
        ("🟡Life Soul", 0.11),
        ("🟡Soul of Hope", 0.18),
        ("🟡Exiled Soul", 0.43),
        ("🟠Vampiric Soul", 0.29),
        ("🟠Time Soul", 0.86),
        ("🟠Prideful Soul", 1.43),
        ("🟠Dual Soul", 3.14),
        ("🟣Solid Soul", 1.16),
        ("🟣Explosive Soul", 1.54),
        ("🟣Fighting Soul", 1.54),
        ("🟣Endurance Soul", 1.54),
        ("🟣Wizard’s Soul", 1.93),
        ("🔵Health Soul", 21.43),
        ("🔵Ki Power Soul", 21.43),
        ("🔵Stamina Soul", 21.43),
        ("🔵Strength Soul", 21.43),
    ]

    # Calculate cumulative probabilities
    cumulative_probabilities = []
    current_sum = 0
    for _, probability in dragon_souls:
        current_sum += probability
        cumulative_probabilities.append(current_sum)

    # Limit the number of spins to avoid excessive spam
    max_spins = 100
    if spins > max_spins:
        await ctx.reply(
            f"⚠️ You can only spin up to {max_spins} times at once.",
            mention_author=False)
        return

    results = []  # Store the results of all spins

    # Perform spins
    for _ in range(spins):
        random_number = random.uniform(
            0, 100)  # Generate a number between 0 and 100
        for index, soul in enumerate(dragon_souls):
            if random_number <= cumulative_probabilities[index]:
                results.append(soul[0])  # Add the selected soul to results
                break

    # Format the results into a single message
    result_message = "\n".join(f"Spin {_+1}: **{soul}**"
                               for _, soul in enumerate(results))

    # Split the result_message into smaller chunks if it's too long
    chunk_size = 1900  # Adjust the chunk size to leave room for extra characters
    for i in range(0, len(result_message), chunk_size):
        await ctx.reply(
            f"🎉 Here are your spin results (Part {i//chunk_size + 1}):\n{result_message[i:i + chunk_size]}",
            mention_author=False)

DB_PATH = "trade_history.db"

# Helper function to get a new database connection
def get_connection():
    # Open a new connection with multithreading support
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# Initialize the database and create tables if they don't exist
def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_name TEXT,
        trade_details TEXT,
        my_value INTEGER,
        their_value INTEGER,
        result TEXT,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

# Call init_db() on startup so the table is ready before any commands are run
init_db()

# Command: Record trade history
@bot.command(name="history", aliases=["hs"])
@allowed_user()
@allowed_channel_silent()
async def history(ctx, *, trade_details: str = None):
    """
    Record a trade in the database and provide a summary of the transaction.
    Use the format: `!history [my_items] with [their_items]`
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")
    if not trade_details:
        await ctx.reply(
            "Please provide trade details in this format:\n`!history [my_items] with [their_items]`",
            mention_author=False,
        )
        return

    # Replace emojis if applicable
    for emoji, name in emoji_to_item.items():
        trade_details = trade_details.replace(emoji, name)

    if " with " not in trade_details:
        await ctx.reply("Invalid format! Use `!history [my_items] with [their_items]`", mention_author=False)
        return

    try:
        my_trade_str, their_trade_str = map(str.strip, trade_details.split(" with "))
    except ValueError:
        await ctx.reply("Error parsing trade details. Ensure the format is correct.", mention_author=False)
        return

    # Parse and calculate trade values
    my_trade = parse_items(my_trade_str)
    their_trade = parse_items(their_trade_str)

    my_value, my_details = calculate_trade_details(my_trade)
    their_value, their_details = calculate_trade_details(their_trade)

    if my_value == their_value:
        result = "Fair Trade"
    elif my_value > their_value:
        result = "You Overpaid"
    else:
        result = "They Overpaid"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get a fresh connection for database operations
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO trades (user_id, user_name, trade_details, my_value, their_value, result, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (ctx.author.id, str(ctx.author), trade_details, my_value, their_value, result, timestamp),
    )
    conn.commit()
    conn.close()

    embed = discord.Embed(title="Trade Recorded", color=discord.Color.blue())
    embed.add_field(name="Your Trade", value=f"**Items:**\n{my_details}\n**Total Value**: {my_value}", inline=False)
    embed.add_field(name="Their Trade", value=f"**Items:**\n{their_details}\n**Total Value**: {their_value}", inline=False)
    embed.add_field(name="Result", value=f"**{result}**", inline=False)
    embed.set_footer(text=f"Trade recorded at {timestamp}")
    await ctx.reply(embed=embed, mention_author=False)

@bot.command(name="myhistory", aliases=["mh"])
@allowed_user()
@allowed_channel_silent()
async def myhistory(ctx):
    """
    Retrieve the user's trade history and insights.
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")
    
    # Open a new connection for this command
    conn = get_connection()
    cursor = conn.cursor()
    
    user_id = ctx.author.id
    cursor.execute(
        "SELECT trade_details, my_value, their_value, result, timestamp FROM trades WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5",
        (user_id,),
    )
    records = cursor.fetchall()
    
    if not records:
        await ctx.reply("No trade history found for you.", mention_author=False)
        conn.close()
        return

    # Calculate trade insights
    cursor.execute(
        "SELECT COUNT(*), AVG(my_value), AVG(their_value) FROM trades WHERE user_id = ?",
        (user_id,),
    )
    total_trades, avg_my_value, avg_their_value = cursor.fetchone()

    embed = discord.Embed(
        title="📜 Your Recent Trade History",
        description=(f"📊 **Total Trades:** {total_trades}\n"
                     f"💰 **Average Your Value:** {avg_my_value:.2f}\n"
                     f"💰 **Average Their Value:** {avg_their_value:.2f}\n\n"),
        color=discord.Color.green(),
    )

    # Add recent trades with formatted details
    for record in records:
        trade_details, my_value, their_value, result, timestamp = record

        if result == "Fair Trade":
            result_emoji = "🟡"
        elif result == "You Overpaid":
            result_emoji = "🔴"
        elif result == "They Overpaid":
            result_emoji = "🟢"
        else:
            result_emoji = "⚪"

    embed.add_field(
        name=f"📅 Trade on {timestamp}",
        value=(f"**🔹 Trade Details:** {robust_replace_item_names_with_emojis(trade_details)}\n"
           f"**🔸 Your Value:** {my_value or 'N/A'}\n"
           f"**🔸 Their Value:** {their_value or 'N/A'}\n"
           f"**🔸 Result:** {result_emoji} {result}\n\n"),
    inline=False,
    )

    embed.set_footer(text="Analyze your trading patterns and improve your strategy!")
    await ctx.reply(embed=embed, mention_author=False)
    conn.close()

@bot.command(name="clearhistory", aliases=["ch"])
@allowed_user()
@allowed_channel_silent()
async def clear_history(ctx):
    """
    Clears the user's trade history from the database.
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")
    
    user_id = ctx.author.id
    conn = get_connection()  # Open a new connection
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM trades WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    await ctx.reply("Your trade history has been cleared.", mention_author=False)

@bot.command(name="suggest", aliases=["st"])
@allowed_user()
@allowed_channel_silent()
async def suggest_trade(ctx, *, offered_item: str = None):
    """
    Suggest trades based on historical data.
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")
    if not offered_item:
        await ctx.reply("Please provide the item you want to trade. Example: `?suggest Frost Aura`", mention_author=False)
        return

    # Check if the offered_item is an emoji and convert it to the item name
    if offered_item in emoji_to_item:
        offered_item = emoji_to_item[offered_item]

    # Use a fresh database connection to query trade suggestions
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT trade_details, COUNT(*) as trade_count FROM trades WHERE trade_details LIKE ? GROUP BY trade_details ORDER BY trade_count DESC LIMIT 3",
        (f"%{offered_item}%", )
    )
    suggestions = cursor.fetchall()
    conn.close()

    if not suggestions:
        await ctx.reply(f"No trade suggestions found for `{offered_item}`. Try trading a more popular item.", mention_author=False)
        return

    # Prepare suggestions text
    suggestion_text = "\n".join([
        f"{idx+1}. {row[0]} (seen in {row[1]} past trades)"
        for idx, row in enumerate(suggestions)
    ])
    # **Perform robust emoji replacements here**
    suggestion_text = robust_replace_item_names_with_emojis(suggestion_text)

    embed = discord.Embed(
        title="Trade Suggestions",
        description=f"Based on historical data, here are suggested trades for `{offered_item}`:",
        color=discord.Color.blue(),
    )
    embed.add_field(name="Suggestions", value=suggestion_text, inline=False)
    embed.set_footer(text="These suggestions are based on community trade patterns.")
    await ctx.reply(embed=embed, mention_author=False)

@bot.command(name="value_suggest", aliases=["vs"])
@allowed_user()
@allowed_channel_silent()
async def suggest_similar_items(ctx, *, item_name: str = None):
    """
    Suggest items with similar values to the given item and provide trade suggestions.
    """
    if not item_name:
        await ctx.reply("Please provide an item name or emoji. Example: `?vs Frost Aura`", mention_author=False)
        return

    # Convert emoji to item name if applicable
    item_name = replace_emojis_with_items(item_name)

    try:
        # Find the item in the dataset
        item_details = enhanced_find_item(data, item_name, case_sensitive=False)
        if isinstance(item_details, str):  # Handles error messages or suggestions
            await ctx.reply(item_details, mention_author=False)
            return

        # Extract the target item's value and demand
        target_value = float(item_details.get('Value', 0))
        target_demand = item_details.get('Demand (out of 10)', "N/A")

        # Create a local copy of the data so as not to modify the global DataFrame
        local_data = data.copy()
        local_data['Value'] = pd.to_numeric(local_data['Value'], errors='coerce')
        local_data.dropna(subset=['Value'], inplace=True)

        # Sort data by value
        local_data = local_data.sort_values(by=['Value'])

        # Find two items below and two items above the target value
        lower_items = local_data[local_data['Value'] < target_value].tail(2)
        higher_items = local_data[local_data['Value'] > target_value].head(2)
        similar_items = pd.concat([lower_items, higher_items])

        # Exclude the target item itself (if present)
        similar_items = similar_items[similar_items['Item name'].str.lower() != item_details['Item name'].lower()]

        # Get emoji for the target item, if available
        target_emoji = next(
            (emoji for emoji, name in emoji_to_item.items() if name.lower() == item_details['Item name'].lower()),
            "❓"
        )

        embed = discord.Embed(
            title=f"🔍 Items with Similar Values to {target_emoji} {item_details['Item name']}",
            description=f"Items with values closest to `{item_details['Item name']}`:",
            color=discord.Color.blue(),
        )
        embed.add_field(
            name="Target Item",
            value=(f"{target_emoji} **{item_details['Item name']}**\n"
                   f"**Value:** {target_value}\n"
                   f"**Demand:** {target_demand}/10"),
            inline=False,
        )

        if not similar_items.empty:
            for _, row in similar_items.iterrows():
                similar_item_name = row['Item name']
                similar_item_emoji = next(
                    (emoji for emoji, name in emoji_to_item.items() if name.lower() == similar_item_name.lower()),
                    "❓"
                )
                value_diff = round((row['Value'] - target_value) / target_value * 100, 2)
                embed.add_field(
                    name=f"{similar_item_emoji} {similar_item_name}",
                    value=(f"**Value:** {row['Value']}\n"
                           f"**Difference:** {value_diff:+}%\n"
                           f"**Demand:** {row['Demand (out of 10)']}/10"),
                    inline=False,
                )
        else:
            embed.add_field(
                name="No Similar Items Found",
                value="No items have a similar value to this item.",
                inline=False,
            )

        # Query trade suggestions from the database using a fresh connection
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT trade_details, COUNT(*) as trade_count FROM trades WHERE trade_details LIKE ? GROUP BY trade_details ORDER BY trade_count DESC LIMIT 3",
            (f"%{item_name}%", )
        )
        trade_suggestions = cursor.fetchall()
        conn.close()

        if trade_suggestions:
            suggestion_text = "\n".join([
                f"- {replace_with_emojis(row[0])} ({row[1]} trades)" for row in trade_suggestions
            ])
            # Use the robust replacement function to ensure correct emoji conversion
            suggestion_text = robust_replace_item_names_with_emojis(suggestion_text)
            embed.add_field(name="🛒 Trade Suggestions", value=suggestion_text, inline=False)
        else:
            embed.add_field(name="🛒 Trade Suggestions", value="No trade suggestions available for this item.", inline=False)

        embed.set_footer(text="Similarity is based on value, demand, and trade data.")
        await ctx.reply(embed=embed, mention_author=False)

    except Exception as e:
        logging.error(f"Error suggesting similar items for '{item_name}': {e}")
        await ctx.reply(f"⚠️ An error occurred while processing your request: {e}", mention_author=False)

@bot.command(name="trends", aliases=["tt"])
@allowed_user()
@allowed_channel_silent()
async def trade_trends(ctx):
    """
    Show trade trends based on historical data.
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")

    # Open a fresh database connection
    conn = get_connection()
    cursor = conn.cursor()

    # Query the top traded items
    cursor.execute("""
        SELECT trade_details, COUNT(*) as trade_count
        FROM trades
        GROUP BY trade_details
        ORDER BY trade_count DESC
        LIMIT 5
    """)
    top_trades = cursor.fetchall()

    # Query most overpaid/underpaid items
    cursor.execute("""
        SELECT trade_details, result, COUNT(*) as frequency
        FROM trades
        WHERE result IN ('You Overpaid', 'They Overpaid')
        GROUP BY trade_details, result
        ORDER BY frequency DESC
        LIMIT 5
    """)
    overpaid_trades = cursor.fetchall()
    conn.close()

    embed = discord.Embed(
        title="📊 Trade Trends",
        description="Discover the latest trading patterns and community behavior:",
        color=discord.Color.gold(),
    )

    # Top trades section
    if top_trades:
        top_trades_list = "\n".join([
            f"**{idx+1}.** {robust_replace_item_names_with_emojis(row[0])} - **{row[1]} trades**"
            for idx, row in enumerate(top_trades)
        ])
        embed.add_field(name="🔥 Top Trades", value=top_trades_list, inline=False)
    else:
        embed.add_field(name="🔥 Top Trades", value="No data available.", inline=False)

    # Divider
    embed.add_field(name="──────────────", value="──────────────", inline=False)

    # Overpaid/Underpaid trades section
    if overpaid_trades:
        overpaid_trades_list = "\n".join([
            f"**{idx+1}.** {robust_replace_item_names_with_emojis(row[0])} - **{row[2]} times** ({row[1]})"
            for idx, row in enumerate(overpaid_trades)
        ])
        embed.add_field(name="⚖️ Most Overpaid/Underpaid Trades", value=overpaid_trades_list, inline=False)
    else:
        embed.add_field(name="⚖️ Most Overpaid/Underpaid Trades", value="No data available.", inline=False)

    embed.set_footer(text="Data is based on past community trades.")
    await ctx.reply(embed=embed, mention_author=False)

TRELLO_API_KEY = os.getenv("TRELLO_API_KEY")
TRELLO_API_SECRET = os.getenv("TRELLO_API_SECRET")
TRELLO_TOKEN = os.getenv("TRELLO_TOKEN")

# Initialize Trello client using env variables
client = TrelloClient(
    api_key=TRELLO_API_KEY,
    api_secret=TRELLO_API_SECRET,
    token=TRELLO_TOKEN
)

# Initialize OpenAI client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY

# Trello board short link 
BOARD_SHORT_LINK = 'GNFgTceY'

CACHE_FILE = "trello_cache.json"

def find_relevant_card(question):
    question_lower = question.lower()
    best_match = None
    highest_score = 0

    for group_name, cards in TRELLO_CARDS.items():
        for card_name, card_data in cards.items():
            # Calculate relevance score
            name_score = fuzz.partial_ratio(question_lower, card_data["name"].lower())
            desc_score = fuzz.partial_ratio(question_lower, card_data["desc"].lower())
            score = max(name_score, desc_score)

            # Keep track of the best match
            if score > highest_score:
                highest_score = score
                best_match = card_data

    return best_match if highest_score > 50 else None  # Adjust threshold as needed

# Trello API credentials
API_KEY = TRELLO_API_KEY,
TOKEN = TRELLO_TOKEN

TRELLO_CARDS = [
    {
        "keywords": ["early game", "starter tips", "level 0-450"],
        "url": "https://api.trello.com/1/cards/6ATM5UDa"  # Early Game Guide
    },
    {
        "keywords": ["mid game", "level 450-855", "progression"],
        "url": "https://api.trello.com/1/cards/rDSlQe2D"  # Mid Game Guide
    },
    {
        "keywords": ["late game", "end game", "level 855-2250"],
        "url": "https://api.trello.com/1/cards/8pFNA4DU"  # Late Game Guide
    },
    {
        "keywords": ["aura skins", "aura skins 1", "frost","boku black aura", "demon 21 aura", "festive aura", "easter aura"],
        "url": "https://api.trello.com/1/cards/xiIDTpse"  # Aura Skins 1
    },
    {
        "keywords": ["aura skins", "aura skins 2", "Halloween Aura", "Halloween 2023 Aura", "Halloween 2024 Aura", "Headless Aura", "Headless Horseman", "Raid Grandmaster Aura", "GM Aura", "Sell Aura", "Shadow SSJ4 Aura", "Shenron Aura", "Easter Aura", "Ultra Instinct Aura"],
        "url": "https://api.trello.com/1/cards/X8J6aMpz"  # Aura Skins 2
    },
    {
    "keywords": ["dragon souls", "ultimate abilities", "obtaining dragon souls", "shattered souls", "permanent soul", "spin npc", "shenron wish"],
    "url": "https://api.trello.com/1/cards/tdnwhBfn"
    },
    {
    "keywords": ["shattered souls", "soulbound", "shattered orb", "spin rates", "dragon soul spin", "locations", "shattered soul locations", "daily luck", "map errors", "soul rates"],
    "url": "https://api.trello.com/1/cards/qC3SfXiT"
    },
    {
    "keywords": ["soul skins", "Despair Soul", "Conqueror Soul", "Halloween event", "visual change", "source soul", "drop rates", "Shenron", "Gp spins", "shattered souls"],
    "url": "https://api.trello.com/1/cards/AzXUUdIF"
    },
    {
    "keywords": ["zenkai souls", "Destruction Soul", "Savior Soul", "transformation", "passive", "fighting style", "moves", "ultimate meter", "Shenron", "Gp spins", "shattered souls"],
    "url": "https://api.trello.com/1/cards/stkfETIJ"
    },
    {
    "keywords": ["legendary souls", "Confident Soul", "Exiled Soul", "Hope Soul", "Life Soul", "transformation", "passive", "fighting style", "moves", "ultimate meter", "Shenron", "Gp spins", "shattered souls"],
    "url": "https://api.trello.com/1/cards/bDHyNTdo"
    },
    {
    "keywords": ["epic souls", "Dual Soul", "Prideful Soul", "Time Soul", "Vampiric Soul", "damage rework", "Shenron", "Gp spins", "shattered souls", "meter charge rate", "transformation", "effects"],
    "url": "https://api.trello.com/1/cards/1rDN2Iy4"
    },
    {
    "keywords": ["rare souls", "Endurance Soul", "Explosive Soul", "Fighting Soul", "Solid Soul", "Wizard's Soul", "damage rework", "Shenron", "Gp spins", "shattered souls", "meter charge rate", "transformation", "effects"],
    "url": "https://api.trello.com/1/cards/o4mYPUzO"
    },
    {
    "keywords": ["uncommon souls", "Health Soul", "Ki Power Soul", "Stamina Soul", "Strength Soul", "passive", "Shenron", "Gp spins", "shattered souls", "meter charge rate", "effects"],
    "url": "https://api.trello.com/1/cards/67ZJlFYY"
    }
]

def get_card_url_from_query(query):
    query_lower = query.lower()
    
    # Step 1: Attempt exact keyword matching first
    for card in TRELLO_CARDS:
        for keyword in card["keywords"]:
            if keyword.lower() in query_lower:
                logging.info(f"Exact match found for query '{query_lower}' in card: {card['url']}")
                return card["url"]
    
    # Step 2: Use fuzzy matching only if no exact match is found
    all_keywords = [keyword for card in TRELLO_CARDS for keyword in card["keywords"]]
    best_match, score = process.extractOne(query_lower, all_keywords)

    logging.info(f"User Query: '{query_lower}' | Best Match: '{best_match}' | Score: {score}")

    # Define a threshold (e.g., 80% match)
    if score > 80:
        for card in TRELLO_CARDS:
            if best_match in card["keywords"]:
                logging.info(f"Match found: {card['url']}")
                return card["url"]
    
    logging.warning(f"No match found for query: '{query_lower}'")
    return None

def fetch_trello_card_data(card_url):
    """
    Fetch the content of a specific Trello card.
    """
    try:
        response = requests.get(
            card_url,
            params={"key": API_KEY, "token": TOKEN}
        )
        
        # Log the full response to see what the Trello API is returning
        logging.info(f"Response status: {response.status_code}")
        logging.info(f"Response body: {response.text}")

        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to fetch Trello card data. Status code: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error fetching Trello card data: {e}")
        return None

def formulate_answer_with_ai(card_data, query):
    """
    Use OpenAI to formulate an answer based on the Trello card data and query.

    Args:
        card_data (dict): The Trello card data.
        query (str): The user query.

    Returns:
        str: The AI-generated answer.
    """
    # Prepare the content to send to OpenAI
    card_name = card_data.get("name", "No Title")
    card_description = card_data.get("desc", "No Description Available")
    prompt = f"""
    You are an assistant for the Dragon Soul Roblox game.

    The following Trello card contains relevant information:
    Title: {card_name}
    Description: {card_description}

    Based on the above information, answer the following user query:
    "{query}"
    """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expert assistant for the Dragon Soul Roblox game."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=500,
            temperature=0,
        )
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        logging.error(f"Error querying OpenAI API: {e}")
        return "⚠️ An error occurred while querying OpenAI. Please try again later."

@bot.command(name="ask", aliases=["a"])
@allowed_user()
@allowed_channel_silent()
async def ask(ctx, *, query: str):
    """
    Respond to user queries by detecting the relevant Trello card and using AI to generate an answer.
    """
    try:
        # Step 1: Get the card URL based on the query
        card_url = get_card_url_from_query(query)
        if not card_url:
            await ctx.reply(
                "❓ I couldn't identify if your query relates to a specific category like Early Game, Mid Game, or Aura Skins. Please clarify or use more specific terms.",
                mention_author=False,
            )
            return

        # Step 2: Fetch the relevant Trello card data
        card_data = fetch_trello_card_data(card_url)
        if not card_data:
            await ctx.reply(
                "⚠️ I found the related category, but I couldn't fetch the data from Trello. Please check back later.",
                mention_author=False,
            )
            return

        # Step 3: Send the Trello data to AI for processing
        answer = formulate_answer_with_ai(card_data, query)

        # Step 4: Handle long answers (Discord 2000 character limit)
        if len(answer) > 2000:
            # Split the answer into chunks and send them one by one
            while len(answer) > 2000:
                await ctx.reply(answer[:2000], mention_author=False)
                answer = answer[2000:]
        
        # Send the final or complete answer
        await ctx.reply(answer, mention_author=False)

    except Exception as e:
        logging.error(f"Error in ?ask command: {e}")
        await ctx.reply(
            "⚠️ An unexpected error occurred while processing your request. Please try again later.",
            mention_author=False,
        )

@bot.command(name='trello')
async def trello(ctx):
    trello_link = "https://trello.com/b/dRDGJZIF/dragon-soul-demo"
    await ctx.reply(
        f"The Trello board contains detailed information about the game, including guides, NPCs, transformations, and more.\nCheck it out here:\n{trello_link}"
    )

# Store active trade challenges
active_challenges = {}

@bot.command(name="challenge", aliases=["tc"])
@allowed_channel_silent()
@allowed_user()
async def challenge(ctx):
    """
    Generates a random trade challenge for users to vote on.
    """
    logging.info(f"Command '{ctx.command}' used by {ctx.author} in channel {ctx.channel}")

    # Load the Excel file
    try:
        df = pd.read_excel("valuedata.xlsx", sheet_name=0)  # Load first sheet
    except Exception as e:
        await ctx.reply(f"❌ Error loading Excel file: {e}", mention_author=False)
        return

    # Ensure the required columns exist
    if "Item name" not in df.columns or "Value" not in df.columns:
        await ctx.reply("❌ Excel file is missing 'Item name' or 'Value' columns.", mention_author=False)
        return

    # Select random items for trade
    items = df.sample(n=5)  # Randomly pick 5 items

    if len(items) < 3:
        await ctx.reply("Not enough items in the Excel file to generate a challenge!", mention_author=False)
        return

    # Select a random item for the user and two items for the trade offer
    user_offer = items.iloc[0]  # First item
    their_offer = items.iloc[1:3]  # Next two items

    user_item_name = user_offer["Item name"]
    user_item_value = user_offer["Value"]
    their_item_names = list(their_offer["Item name"])
    their_item_value = their_offer["Value"].sum()

    # Store challenge for voting
    trade_id = ctx.author.id
    active_challenges[trade_id] = {
        "user_offer": user_offer,
        "their_offer": their_offer
    }

    # Build the embed
    embed = discord.Embed(title="📜 Trade Challenge", color=discord.Color.blue())
    embed.add_field(name="Your Offer:", value=f"🔥 {user_item_name} (**{user_item_value}**)", inline=False)
    embed.add_field(name="Their Offer:", value=f"💀 {their_item_names[0]} + ❄️ {their_item_names[1]} (**{their_item_value}**)", inline=False)
    embed.add_field(name="❓ Decision", value="Would you take this trade? (`!w` or `!l`)", inline=False)
    embed.set_footer(text="Vote with !w (Win) or !l (Loss)")

    await ctx.reply(embed=embed, mention_author=False)

@bot.command(name="w")
@allowed_channel_silent()
async def vote_win(ctx):
    """
    Vote that the trade challenge is a Win.
    """
    if ctx.author.id not in active_challenges:
        await ctx.reply("No active trade challenge found! Use `!challenge` first.", mention_author=False)
        return

    trade = active_challenges.pop(ctx.author.id)
    await ctx.reply(f"✅ You voted **Win** for this trade!", mention_author=False)

@bot.command(name="l")
@allowed_channel_silent()
async def vote_loss(ctx):
    """
    Vote that the trade challenge is a Loss.
    """
    if ctx.author.id not in active_challenges:
        await ctx.reply("No active trade challenge found! Use `!challenge` first.", mention_author=False)
        return

    trade = active_challenges.pop(ctx.author.id)
    await ctx.reply(f"❌ You voted **Loss** for this trade!", mention_author=False)

# Connect to SQLite database (creates file if not exists)
conn = sqlite3.connect("vouch_system.db")
cursor = conn.cursor()

# Create table if not exists (initial creation may include UNIQUE constraint)
cursor.execute("""
CREATE TABLE IF NOT EXISTS vouches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vouched_user_id INTEGER,
    vouched_user_name TEXT,
    vouching_user_id INTEGER,
    vouching_user_name TEXT,
    reason TEXT,
    timestamp TEXT,
    UNIQUE(vouched_user_id, vouching_user_id)
)
""")
conn.commit()

def migrate_remove_unique():
    # Check if the unique constraint exists
    cursor.execute("PRAGMA index_list(vouches)")
    indexes = cursor.fetchall()
    unique_found = False
    for index in indexes:
        # Each index tuple: (seq, name, unique, origin, partial)
        seq, index_name, unique, origin, partial = index
        if unique:
            cursor.execute(f"PRAGMA index_info({index_name})")
            cols = [row[2] for row in cursor.fetchall()]  # row: (seqno, cid, name)
            if set(cols) == {"vouched_user_id", "vouching_user_id"}:
                unique_found = True
                break

    if unique_found:
        print("Unique constraint found. Running migration to remove it.")
        cursor.execute("""
            CREATE TABLE vouches_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vouched_user_id INTEGER,
                vouched_user_name TEXT,
                vouching_user_id INTEGER,
                vouching_user_name TEXT,
                reason TEXT,
                timestamp TEXT
            )
        """)
        # Copy data from old table to new table.
        cursor.execute("""
            INSERT INTO vouches_new (id, vouched_user_id, vouched_user_name, vouching_user_id, vouching_user_name, reason, timestamp)
            SELECT id, vouched_user_id, vouched_user_name, vouching_user_id, vouching_user_name, reason, timestamp FROM vouches
        """)
        conn.commit()
        # Drop the old table.
        cursor.execute("DROP TABLE vouches")
        # Rename new table to the original name.
        cursor.execute("ALTER TABLE vouches_new RENAME TO vouches")
        conn.commit()
        print("Migration complete. UNIQUE constraint removed.")
    else:
        print("No unique constraint found on (vouched_user_id, vouching_user_id).")

migrate_remove_unique()

# --- Vouch Command ---
# Command: Vouch for a user (usage: !vouch @User [reason])
@bot.command(name="vouch")
@allowed_user()
@allowed_channel_silent()
async def vouch(ctx, user: discord.Member, *, reason: str = None):
    # Ensure exactly one user is mentioned.
    if len(ctx.message.mentions) != 1:
        await ctx.reply("⚠️ Please mention exactly one user to vouch for.", mention_author=False)
        return

    if user.id == ctx.author.id:
        await ctx.reply("❌ You cannot vouch for yourself!", mention_author=False)
        return

    # If no reason is provided, use a default message.
    if reason is None or reason.strip() == "":
        reason = "No reason provided."

    # Insert the new vouch into the database.
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO vouches (vouched_user_id, vouched_user_name, vouching_user_id, vouching_user_name, reason, timestamp) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user.id, str(user), ctx.author.id, str(ctx.author), reason, current_time))
    conn.commit()

    await ctx.reply(f"✅ You have vouched for {user.mention} for **'{reason}'**!", mention_author=False)

# Command: View your own vouches
@bot.command(name="myvouches")
@allowed_user()
@allowed_channel_silent()
async def myvouches(ctx):
    cursor.execute("SELECT COUNT(*) FROM vouches WHERE vouched_user_id = ?", (ctx.author.id,))
    vouch_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT vouching_user_name, reason, timestamp 
        FROM vouches 
        WHERE vouched_user_id = ? 
        ORDER BY timestamp DESC LIMIT 5
    """, (ctx.author.id,))
    vouch_logs = cursor.fetchall()

    embed = discord.Embed(title="👤 Your Vouch Summary", description=f"You have **{vouch_count}** vouches!", color=discord.Color.blue())
    if vouch_logs:
        for voucher, vouch_reason, ts in vouch_logs:
            embed.add_field(name=f"From {voucher}", value=f"📝 Reason: {vouch_reason}\n📅 Date: {ts}", inline=False)
    await ctx.reply(embed=embed, mention_author=False)

# Command: View someone else's vouches
@bot.command(name="vouches")
@allowed_user()
@allowed_channel_silent()
async def vouches(ctx, user: discord.Member):
    cursor.execute("SELECT COUNT(*) FROM vouches WHERE vouched_user_id = ?", (user.id,))
    vouch_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT vouching_user_name, reason, timestamp 
        FROM vouches 
        WHERE vouched_user_id = ? 
        ORDER BY timestamp DESC LIMIT 5
    """, (user.id,))
    vouch_logs = cursor.fetchall()

    embed = discord.Embed(title=f"👤 {user.display_name}'s Vouches", description=f"{user.mention} has **{vouch_count}** vouches!", color=discord.Color.green())
    if vouch_logs:
        for voucher, vouch_reason, ts in vouch_logs:
            embed.add_field(name=f"From {voucher}", value=f"📝 Reason: {vouch_reason}\n📅 Date: {ts}", inline=False)
    await ctx.reply(embed=embed, mention_author=False)

# Command: Vouch leaderboard
@bot.command(name="vouchleaderboard", aliases=["vouchlb"])
@allowed_user()
@allowed_channel_silent()
async def vouch_leaderboard(ctx):
    cursor.execute("""
        SELECT vouched_user_id, vouched_user_name, COUNT(*) as vouch_count 
        FROM vouches 
        GROUP BY vouched_user_id 
        ORDER BY vouch_count DESC 
        LIMIT 5
    """)
    top_vouches = cursor.fetchall()

    if not top_vouches:
        await ctx.reply("🏆 No vouches recorded yet!", mention_author=False)
        return

    leaderboard = "\n".join([f"**{idx+1}.** {vouched_name} - **{count}** vouches" 
                              for idx, (uid, vouched_name, count) in enumerate(top_vouches)])
    embed = discord.Embed(title="🏆 Top 5 Most Vouched Users", description=leaderboard, color=discord.Color.gold())
    await ctx.reply(embed=embed, mention_author=False)

# Command: Remove all vouches for a user (admin/allowed users only)
@bot.command(name="removevouch")
@allowed_user()
@allowed_channel_silent()
async def remove_vouch(ctx, user: discord.Member):
    cursor.execute("DELETE FROM vouches WHERE vouched_user_id = ?", (user.id,))
    conn.commit()
    await ctx.reply(f"🗑️ Removed all vouches for {user.mention}.", mention_author=False)

# Error handler for removevouch missing permissions
@remove_vouch.error
async def remove_vouch_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("⚠️ You don't have permission to remove vouches!", mention_author=False)

@bot.command(name="printvouches")
@allowed_user()
@allowed_channel_silent()
async def print_vouches(ctx):
    cursor.execute("SELECT * FROM vouches")
    rows = cursor.fetchall()
    print("---- Vouches Database ----")
    for row in rows:
        print(row)
    print("---- End Vouches Database ----")
    await ctx.reply("✅ Vouches database printed to console.", mention_author=False)

# Command: Vouches Menu (lists all vouch commands)
@bot.command(name="vouchesmenu")
@allowed_user()
@allowed_channel_silent()
async def vouches_menu(ctx):
    embed = discord.Embed(
        title="📜 Vouches Menu",
        description="Here are the available vouch commands and their usage:",
        color=discord.Color.purple()
    )
    embed.add_field(name="!vouch @User [reason]", value="Vouch for a user with an optional reason.", inline=False)
    embed.add_field(name="!myvouches", value="View your own vouches and recent vouch logs.", inline=False)
    embed.add_field(name="!vouches @User", value="View another user's vouches and recent logs.", inline=False)
    embed.add_field(name="!vouchleaderboard or !vouchlb", value="See the top 5 most vouched users.", inline=False)
    embed.set_footer(text="Use these commands in an allowed channel.")
    await ctx.reply(embed=embed, mention_author=False)

@bot.event
async def on_message(message):
    if message.author.bot:
        return  # Ignore messages from bots

    # Define command aliases
    aliases = {
        "value": ["v", "item_details"],
        "history": ["th", "trade_history"],
        "myhistory": ["mh", "my_trades"],
        "suggest": ["st", "recommend_trade"],
        "value_suggest": ["vs", "trade_value"],
        "trends": ["tt", "top_trades"],
        "help": ["h", "menu"],
    }

    # Check if the message starts with the prefix
    if message.content.startswith("!"):
        user_input = message.content[1:].split()[0]  # Extract the command part

        # Check for aliases and replace with the actual command
        for command, alias_list in aliases.items():
            if user_input in alias_list:
                message.content = f"!{command}{message.content[len(user_input)+1:]}"
                break

    # Process the command normally
    await bot.process_commands(message)

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
bot.run(DISCORD_TOKEN)