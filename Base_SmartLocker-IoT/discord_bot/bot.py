
# Modularized, modern Discord bot with slash commands, embeds, and buttons
import discord
from discord import app_commands, Interaction, Embed, ButtonStyle
from discord.ext import commands
from discord.ui import View, button
import os
from dotenv import load_dotenv
import requests

load_dotenv()
TOKEN = os.getenv('BOT_TOKEN')
DOOR_API_URL = os.getenv('DOOR_API_URL', 'http://192.168.1.36')

class DoorAPI:
    @staticmethod
    def get_status():
        try:
            resp = requests.get(f"{DOOR_API_URL}/status", timeout=2)
            data = resp.json()
            if data.get('locked') is None:
                return None, 'Device offline.'
            return data['locked'], None
        except Exception:
            return None, 'Device offline.'

    @staticmethod
    def set_status(locked: bool):
        try:
            resp = requests.post(f"{DOOR_API_URL}/lock", json={"locked": locked}, timeout=2)
            data = resp.json()
            if data.get('locked') is None:
                return None, 'Failed to update. Device offline.'
            return data['locked'], None
        except Exception:
            return None, 'Failed to update. Device offline.'

def build_status_embed(locked: bool|None, error: str|None = None) -> Embed:
    embed = Embed(title="🔒 IoT Door Status", color=0xe53935 if locked else 0x43a047)
    if error:
        embed.description = f"❌ {error}"
        embed.color = 0x757575
    elif locked is not None:
        embed.description = f"Door is **{'Locked' if locked else 'Unlocked'}**."
        embed.add_field(name="Status", value=("🔴 Locked" if locked else "🟢 Unlocked"), inline=True)
    else:
        embed.description = "Status unknown."
    return embed

class DoorControlView(View):
    def __init__(self, locked: bool|None, disabled: bool = False):
        super().__init__(timeout=60)
        self.locked = locked
        self.disable_all = disabled

    @button(label="Lock", style=ButtonStyle.danger, custom_id="lock")
    async def lock_button(self, interaction: Interaction, button):
        if self.disable_all:
            await interaction.response.send_message("Buttons are disabled.", ephemeral=True)
            return
        locked, error = DoorAPI.set_status(True)
        embed = build_status_embed(locked, error)
        await interaction.response.edit_message(embed=embed, view=DoorControlView(locked, error is not None))

    @button(label="Unlock", style=ButtonStyle.success, custom_id="unlock")
    async def unlock_button(self, interaction: Interaction, button):
        if self.disable_all:
            await interaction.response.send_message("Buttons are disabled.", ephemeral=True)
            return
        locked, error = DoorAPI.set_status(False)
        embed = build_status_embed(locked, error)
        await interaction.response.edit_message(embed=embed, view=DoorControlView(locked, error is not None))

class DoorBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        await self.tree.sync()

bot = DoorBot()

@bot.tree.command(name="status", description="Show the current door status and controls.")
async def status_command(interaction: Interaction):
    locked, error = DoorAPI.get_status()
    embed = build_status_embed(locked, error)
    view = DoorControlView(locked, error is not None)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=False)

if __name__ == '__main__':
    bot.run(TOKEN)
