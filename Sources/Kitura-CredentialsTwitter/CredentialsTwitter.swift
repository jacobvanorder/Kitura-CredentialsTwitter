/**
 * Copyright Jacob Van Order 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Kitura
import KituraNet
import LoggerAPI
import Credentials

import SwiftyJSON

import Foundation

public class CredentialsTwitter: CredentialsPluginProtocol {

    let consumerKey: String
    let consumerSecret: String

    private var oAuthToken: String = ""
    private var oAuthTokenSecret: String = ""
    private var oAuthTokenVerifier: String = ""

    public init(consumerKey: String,
                consumerSecret: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
    }

    /// CredentialsPluginProtocol

    /// The name of the plugin.
    public var name: String {
        return "Twitter"
    }

    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?

    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return true
    }

    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate?

    /// Authenticate an incoming request.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication data (usually an authentication token) in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public func authenticate (request: RouterRequest, response: RouterResponse,
                              options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                              onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                              onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                              inProgress: @escaping () -> Void) {
        if let verifier = request.queryParameters["oauth_verifier"],
            let newOAuthToken = request.queryParameters["oauth_token"],
            newOAuthToken == oAuthToken {
            oAuthTokenVerifier = verifier
            twitterAccessTokenRequest(request: request,
                                      response: response,
                                      onSuccess: onSuccess,
                                      onFailure: onFailure,
                                      onPass: onPass)
        }
        else {
            twitterTokenRequest(request: request,
                                response: response,
                                onFailure: onFailure,
                                onPass: onPass,
                                inProgress: inProgress)
        }
    }

    //MARK: Step 1: Obtaining a request token
    func twitterTokenRequest(request: RouterRequest,
                             response: RouterResponse,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {
        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("api.twitter.com"))
        requestOptions.append(.method("POST"))
        requestOptions.append(.path("oauth/request_token"))
        var headers = [String: String]()
        var parameters = [String:String]()

        let nonce = String.nonce
        let timeStamp = Date().timeIntervalSince1970.roundedString

        parameters["oauth_consumer_key"] = consumerKey
        parameters["oauth_signature_method"] = "HMAC-SHA1"
        parameters["oauth_timestamp"] = timeStamp
        parameters["oauth_nonce"] = nonce
        parameters["oauth_version"] = "1.0"

        guard let signature = String.oAuthSignature(fromMethod: "POST",
                                                    urlString: "https://api.twitter.com/oauth/request_token",
                                                    parameters: parameters,
                                                    consumerSecret: consumerSecret) else {
                                                        onFailure(nil, nil)
                                                        return
        }

        parameters["oauth_signature"] = signature

        headers["Authorization"] = String.oAuthAuthorizationString(fromParameters: parameters)
        requestOptions.append(.headers(headers))

        let twitterRequest = HTTP.request(requestOptions) {
            (optionalResponse) in
            guard let tokenResponse = optionalResponse, tokenResponse.statusCode == HTTPStatusCode.OK else {
                onFailure(optionalResponse?.statusCode, nil)
                return
            }

            var body = Data()
            do {
                try tokenResponse.readAllData(into: &body)
                let string = String(data: body, encoding: String.Encoding.utf8)
                guard let fields = string?.components(separatedBy: "&") else {
                    onPass(tokenResponse.statusCode, .none)
                    return
                }
                var responseDictionary = [String: String]()
                for field in fields {
                    let keyValue = field.components(separatedBy: "=")
                    if let key = keyValue.first,
                        let value = keyValue.last {
                        responseDictionary[key] = value
                    }
                    else {
                        onPass(tokenResponse.statusCode, .none)
                        return
                    }
                }

                guard let token = responseDictionary["oauth_token"],
                    let secret = responseDictionary["oauth_token_secret"] else {
                        onFailure(nil, nil)
                        return
                }

                self.oAuthToken = token
                self.oAuthTokenSecret = secret

                self.twitterRedirect(request: request,
                                     response: response,
                                     onFailure: onFailure,
                                     inProgress: inProgress)
            }
            catch {
                onFailure(nil, nil)
            }
        }

        twitterRequest.end()
    }

    //MARK: Step 2: Redirecting the user
    func twitterRedirect(request: RouterRequest,
                         response: RouterResponse,
                         onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                         inProgress: @escaping () -> Void) {
        do {
            _ = try response.redirect("https://api.twitter.com/oauth/authenticate?oauth_token=\(oAuthToken)")
            inProgress()
        }
        catch {
            Log.error("Could not redirect to Twitter")
            onFailure(nil, nil)
        }
    }

    //MARK: Step 3: Step 3: Converting the request token to an access token
    func twitterAccessTokenRequest(request: RouterRequest,
                                   response: RouterResponse,
                                   onSuccess: @escaping (UserProfile) -> Void,
                                   onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                                   onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void) {
        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("api.twitter.com"))
        requestOptions.append(.method("POST"))
        requestOptions.append(.path("oauth/access_token"))
        var headers = [String: String]()
        var parameters = [String:String]()

        let nonce = String.nonce
        let timeStamp = Date().timeIntervalSince1970.roundedString

        parameters["oauth_consumer_key"] = consumerKey
        parameters["oauth_nonce"] = nonce
        parameters["oauth_signature_method"] = "HMAC-SHA1"
        parameters["oauth_timestamp"] = timeStamp
        parameters["oauth_token"] = oAuthToken
        parameters["oauth_version"] = "1.0"
        parameters["oauth_verifier"] = oAuthTokenVerifier

        let url = "https://api.twitter.com/oauth/access_token?oauth_verifier=\(oAuthTokenVerifier)"
        guard let signature = String.oAuthSignature(fromMethod: "POST",
                                                    urlString: url,
                                                    parameters: parameters,
                                                    consumerSecret: consumerSecret,
                                                    oAuthToken: oAuthTokenSecret) else {
                                                        onFailure(nil, nil)
                                                        return
        }
        parameters["oauth_signature"] = signature

        headers["Authorization"] = String.oAuthAuthorizationString(fromParameters: parameters)
        requestOptions.append(.headers(headers))

        let twitterRequest = HTTP.request(requestOptions) {
            (optionalResponse) in
            guard let accessTokenResponse = optionalResponse, accessTokenResponse.statusCode == .OK else {
                Log.error("Twitter access token response returned with \(optionalResponse?.statusCode)")
                onFailure(optionalResponse?.statusCode, nil)
                return
            }

            var body = Data()
            do {
                try accessTokenResponse.readAllData(into: &body)
                let string = String(data: body, encoding: .utf8)

                var responseDictionary = [String: String]()
                guard let fields = string?.components(separatedBy: "&") else {
                    onPass(accessTokenResponse.statusCode, .none)
                    return
                }

                for field in fields {
                    let keyValue = field.components(separatedBy: "=")
                    if let key = keyValue.first,
                        let value = keyValue.last {
                        responseDictionary[key] = value
                    }
                    else {
                        onPass(accessTokenResponse.statusCode, .none)
                        return
                    }
                }

                guard let id = responseDictionary["user_id"],
                    let displayName = responseDictionary["screen_name"],
                    let newOAuthToken = responseDictionary["oauth_token"],
                    let newOAuthTokenSecret = responseDictionary["oauth_token_secret"] else {
                        Log.error("Twitter access token response not correct.")
                        onFailure(nil, nil)
                        return
                }

                self.oAuthToken = newOAuthToken
                self.oAuthTokenSecret = newOAuthTokenSecret

                let user = UserProfile(id: id,
                                       displayName: displayName,
                                       provider: self.name)
                self.userProfileDelegate?.update(userProfile: user, from: responseDictionary)
                onSuccess(user)
            }
            catch {
                Log.error("Twitter access token response could not read body data.")
                onFailure(nil, nil)
            }
        }

        twitterRequest.end()
    }
}
