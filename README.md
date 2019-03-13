# driveperms
Quick app for finding accessible drive objects that have a shareable link.

It does two things:

1. Asks for OAuth2 credentials with drive metadata access
2. Serves up anything in the returned list that has an external link, so you can go find it and audit its permissions.

No server-side state is kept. OAuth2 creds are stored in Flask's encrypted cookie-based session store, and the session is forgotten on browser close (default Flask settings).
