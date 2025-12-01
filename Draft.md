## Producer terminal
- Access their camera and extract QRcode in real time.
- Fetch the standard time
- Send back to the server (event driven, send if code change)

## Consumer terminal
- Get the real time url with remaining time

## Server terminal

### User statistics
- Display total number of users
- Display number of live users
- Display number of live Producer
- Leaderboard

### User management
- User id and password
- Their channel id
- Their customized bios
- User contribution count

### Log
- Record url with timestamp
- Record user login ip and time

### Live channel created by Producer
- Receive {url, timestamp, channel id} real time and forword to paired consumer(s) with remaining available time (assume expire time variable is 10s)
- Server will need to calculate the remaining time. It may be unknown, or n seconds (server recogonize the change)
- password function

### Privacy policy
- no photos or videos would be upload to the server, only url and time would.
- online status will be recorded, including IP address (for account abuse detection), time (for [user statistics](#user-statistics)), and user id. 

### Hall(Not considering at the moment)
Providers and consumers can reach an agreement or even a deal in advance.


---
*some expectations*
- It should be compatible with docker, CF worker, and so on.
