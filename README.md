# Kitura-CredentialsTwitter

A plugin for the Kitura-Credentials framework that authenticates using the Twitter OAuth web login

![Mac OS X](https://img.shields.io/badge/os-Mac%20OS%20X-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)

## Summary
Plugins for [Kitura-Credentials](https://github.com/IBM-Swift/Kitura-Credentials) framework that authenticate using the [Twitter's “Sign In with Twitter” ](https://dev.twitter.com/web/sign-in/implementing).

## Swift Version

This requires Swift 3.0 and above. You can download this version of the Swift binaries by following this [link](https://swift.org/download/).

## Before You Start

Head on over to [Twitter's Application Management](https://apps.twitter.com) page and register an application you'll be using Kitura for. You'll need to give a website (which can be fake for now) and a callback URL which you'll be using during these instructions. For instance: `http://localhost:8090/login/twitter/callback`.

After you create the application on Twitter, gather the Consumer Key and Consumer Secret from your application's Keys and Access Tokens page.

## Example of Twitter Web Login

_Note: for more detailed instructions, please refer to [Kitura-Credentials-Sample](https://github.com/IBM-Swift/Kitura-Credentials-Sample)._

First, set up the session:

```swift
import KituraSession

router.all(middleware: Session(secret: "Some random string"))
```

Create an instance of `CredentialsTwitter` plugin and register it with `Credentials` framework:

```swift
import Credentials
import Kitura_CredentialsTwitter

let credentials = Credentials()
let twitter = CredentialsTwitter(consumerKey: twitterConsumerKey,
                                 consumerSecret: twitterConsumerSecret)
credentials.register(twitter)
```

**Where:**
   - *twitterConsumerKey* is the Consumer Key of your app in the Twitter Application Portal
   - *twitterConsumerSecret* is the Consumer Secret of your app in the Twitter Application Portal

**Note:** Twitter has you specify your callback URL on your application's detail page of the Twitter Application Portal.

Specify where to redirect non-authenticated requests:
```swift
   credentials.options["failureRedirect"] = "/login/twitter"
```

Connect `credentials` middleware to requests to `/private`:

```swift
router.all("/private", middleware: credentials)
router.get("/private/data", handler:
    { request, response, next in
        ...  
        next()
})
```
And call `authenticate` to login with Twitter and to handle the redirect (callback) from the Twitter login web page after a successful login:

```swift
router.get("/login/twitter",
           handler: credentials.authenticate(twitter.name))

router.get("/login/twitter/callback",
           handler: credentials.authenticate(twitter.name))
```

## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](LICENSE.txt).
