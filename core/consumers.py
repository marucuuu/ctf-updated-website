import json
from channels.generic.websocket import AsyncWebsocketConsumer # type: ignore

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Add the user to the notification group asynchronously
        self.user = self.scope["user"]
        self.group_name = f"user_{self.user.id}"
        
        # Join the group for real-time updates
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Remove the user from the notification group asynchronously
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def send_notification(self, event):
        # Send the notification to the WebSocket asynchronously
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'sender': event['sender'],
            'created_at': event['created_at'],
        }))

    async def send_last_report_update(self, event):
        # This method sends the updated last report date to the WebSocket
        await self.send(text_data=json.dumps({
            'last_report_date': event['last_report_date'],  # Send the updated last report date
        }))
