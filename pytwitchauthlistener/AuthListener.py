from aiohttp import web
import asyncio
from twitchAPI.twitch import Twitch, TwitchAPIException
from twitchAPI.oauth import validate_token, UserAuthenticator


class AuthListener:
    def __init__(
        self,
        clientID,
        clientSecret,
        targetScope,
        redirectHost,
        listenPort,
        reauthCallback,
    ):
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.targetScope = targetScope
        self.redirectHost = redirectHost
        self.listenPort = listenPort
        self.reauthCallback = reauthCallback

    async def initialise(self):
        self.twitch = Twitch(self.clientID, self.clientSecret)
        self.auth = UserAuthenticator(
            self.twitch,
            self.targetScope,
            url=f"{self.redirectHost}/auth",
            force_verify=True,
        )

        self.app = web.Application()
        self.app.add_routes([web.get("/auth", self.authHandler)])
        self.app.add_routes([web.get("/login", self.createHandler)])

        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, port=self.listenPort)
        await site.start()

    async def shutdown(self):
        print("Cleaning up web server")
        await self.runner.cleanup()

    async def createHandler(self, request):
        return web.HTTPFound(self.auth.return_auth_url())

    async def authHandler(self, request):
        state = request.rel_url.query["state"]
        if state != self.auth.state:
            return web.Response(text="Bad state.", status=401)
        code = request.rel_url.query["code"]
        if code is None:
            return web.Response(text="Missing code.", status=400)
        try:
            token, refresh = await self.auth.authenticate(user_token=code)
            validate = await validate_token(token)

            if self.reauthCallback:
                apiKey = await self.reauthCallback(
                    validate["user_id"],
                    validate["login"],
                    token,
                    refresh,
                )
            else:
                return web.Response(text=f"Internal error - no auth listener.'\n")
        except TwitchAPIException as e:
            return web.Response(text="Failed to generate auth token.", status=400)
        return web.Response(
            text="Sucessfully authenticated! You can now close this browser window."
        )
