# Telegram Bot Example

This is an example Telegram bot implementation using the x402 Solana ADK platform.

## Setup

1. Create a bot with @BotFather on Telegram
2. Get your bot token
3. Set webhook URL

## Usage

```typescript
import { TelegramBot } from '@x402/solana-adk/telegram';

const bot = new TelegramBot({
  token: 'YOUR_BOT_TOKEN',
  webhookUrl: 'https://your-domain.com/api/telegram/webhook'
});

// Set webhook
await bot.setWebhook('https://your-domain.com/api/telegram/webhook');
```

