## Producer terminal
- Access their camera and extract QRcode in real time.
- Fetch the standard time
- Send back to the server

## Consumer terminal
- Get the real time url with remaining time

## Server terminal

### User static
- Display total number of users
- Display number of live users
- Display number of live Producer

### User management
- User id and password
- Their channel id
- Their customized bios

### Log
- Record url with timestamp
- Record user login ip and time

### Live channel created by Producer
- Receive {url, timestamp, channel id} real time and forword to paired cunsumer(s) with remaining available time (assume expire time variable is 10s)
- Server will need to calculate the remaining time. It may be unknown, or n seconds (server recogonize the change)
- password function

### Privacy policy
- no photos or videos would be upload to the server, only url and time would.
- online status will be recorded, including IP address (for account abuse detection), time (for [user static](#user-static)), and user id. 

### Hall(Not considering at the moment)
Providers and consumers can reach an agreement or even a deal in advance.
