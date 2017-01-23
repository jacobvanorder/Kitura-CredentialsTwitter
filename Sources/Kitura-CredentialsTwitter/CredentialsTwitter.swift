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

let oAuthTokenKey = "oauth_token"
let oAuthTokenSecretKey = "oauth_token_secret"
let oAuthVerifierKey = "oauth_verifier"
let userIDKey = "user_id"
let screenNameKey = "screen_name"

/// CredentialsTwitter is a plugin for the Credentials framework that authenticate using Twitter. This plugin uses
/// Twitter's [“Sign in with Twitter”](https://dev.twitter.com/web/sign-in/implementing) use case. Roughly, there are
/// three steps to this process: obtaining a request token, redirecting the user, and converting the request token to
/// an access token. These three steps are marked down below. The goal of this process is create a UserProfile to give
/// back to Credentials.

public class CredentialsTwitter: CredentialsPluginProtocol {
    
    /// You must register an app at https://apps.twitter.com in order to get the consumer key.
    let consumerKey: String
    
    /// You must register an app at https://apps.twitter.com in order to get the consumer secret.
    let consumerSecret: String
    
    private var oAuthToken: String = ""
    private var oAuthTokenSecret: String = ""
    private var oAuthTokenVerifier: String = ""
    
    /// Initialization method used to gather the consumer key and consumer secret used by Twitter.
    ///
    /// - Parameters:
    ///   - consumerKey: The consumer key gathered from https://apps.twitter.com for your application.
    ///   - consumerSecret: The consumer secret gathered from https://apps.twitter.com for your application.
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
    public func authenticate(request: RouterRequest,
                             response: RouterResponse,
                             options: [String:Any],
                             onSuccess: @escaping (UserProfile) -> Void,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {
        
        guard let verifier = request.queryParameters[oAuthVerifierKey],
            let newOAuthToken = request.queryParameters[oAuthTokenKey],
            newOAuthToken == oAuthToken else { // Start with Step 1.
                tokenRequest(request: request,
                             response: response,
                             onFailure: onFailure,
                             onPass: onPass,
                             inProgress: inProgress)
                return
        }
        
        // If Step 2, is accomplished, the query will have `oauth_verifier` and `oauth_token`. The oauth_token should
        // match the OAuthToken you got during Step 1.
        oAuthTokenVerifier = verifier
        accessTokenRequest(request: request,
                           response: response,
                           onSuccess: onSuccess,
                           onFailure: onFailure,
                           onPass: onPass)
    }
    
    //MARK: Step 1: Obtaining a request token
    
    /// The method gathers the necessary components to create a request to https://api.twitter.com/oauth/request_token.
    /// If the request is successful, it will move on to Step 2 which redirects the user. Failure or incorrect payloads
    /// call `onFailure` or `onPass`, respectively.
    ///
    /// - Parameters:
    ///   - request: The `RouterRequest` object used to get information about the request.
    ///   - response: The `RouterResponse` object used to respond to the request.
    ///   - onFailure: The closure to invoke in the case of an authentication failure.
    ///   - onPass: The closure to invoke when the plugin doesn't recognize the authentication data (usually an
    ///       authentication token) in the request.
    ///   - inProgress: The closure to invoke to cause a redirect to the login page in the case of redirecting
    ///       authentication.
    private func tokenRequest(request: RouterRequest,
                      response: RouterResponse,
                      onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                      onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                      inProgress: @escaping () -> Void) {
        var requestOptions: [ClientRequest.Options] = [.schema("https://"),
                                                       .hostname("api.twitter.com"),
                                                       .method("POST"),
                                                       .path("oauth/request_token")]
        var headers = [String : String]()

        let nonce = String.nonce
        let timeStamp = Date().timeIntervalSince1970.roundedString

        var parameters = ["oauth_consumer_key" : consumerKey,
                          "oauth_signature_method" : "HMAC-SHA1",
                          "oauth_timestamp" : timeStamp,
                          "oauth_nonce" : nonce,
                          "oauth_version" : "1.0"]
        
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
                Log.error("Twitter token response returned with \(optionalResponse?.statusCode)")
                onFailure(optionalResponse?.statusCode, nil)
                return
            }
            
            var body = Data()
            do {
                try tokenResponse.readAllData(into: &body)
                let string = String(data: body, encoding: String.Encoding.utf8)
                guard let fields = string?.components(separatedBy: "&") else {
                    Log.error("Twitter token response not correct format: \(string)")
                    onPass(tokenResponse.statusCode, .none)
                    return
                }
                var responseDictionary = [String : String]()
                for field in fields {
                    let keyValue = field.components(separatedBy: "=")
                    if let key = keyValue.first,
                        let value = keyValue.last {
                        responseDictionary[key] = value
                    }
                    else {
                        Log.error("Twitter token response not correct format: \(string)")
                        onPass(tokenResponse.statusCode, .none)
                        return
                    }
                }
                
                guard let token = responseDictionary["oauth_token"],
                    let secret = responseDictionary["oauth_token_secret"] else {
                        Log.error("Twitter token response did not contain oauth_token or oauth_token_secret.")
                        onPass(tokenResponse.statusCode, .none)
                        return
                }
                
                self.oAuthToken = token
                self.oAuthTokenSecret = secret
                
                //Go to Step 2
                self.authorizationRedirect(request: request,
                                           response: response,
                                           onFailure: onFailure,
                                           inProgress: inProgress)
            }
            catch {
                Log.error("Twitter token response could not read body data.")
                onFailure(nil, nil)
            }
        }
        
        twitterRequest.end()
    }
    
    //MARK: Step 2: Redirecting the user
    
    /// This method uses the RouterResponse to redirect the user to https://api.twitter.com/oauth/authenticate. It adds
    /// a query using the OAuth Token obtained during Step 1. The result of this action will loop back to `func
    /// authenticate(request, response, options, onSuccess, onFailure, onPass, inProgress)`.
    ///
    /// - Parameters:
    /// - request: The `RouterRequest` object used to get information about the request.
    /// - response: The `RouterResponse` object used to respond to the request.
    /// - onFailure: The closure to invoke in the case of an authentication failure.
    /// - inProgress: The closure to invoke to cause a redirect to the login page in the case of redirecting
    ///       authentication.
    private func authorizationRedirect(request: RouterRequest,
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
    
    //MARK: Step 3: Converting the request token to an access token
    
    
    /// The method gathers the necessary components to create a request to https://api.twitter.com/oauth/access_token.
    /// At this point, a valid OAuth Token, OAuth Secret, and OAuth Verifier, gathered during Steps 1 and 2 should be
    /// valid. If the request is successful, it will move on to Step 2 which redirects the user. Failure or incorrect
    /// payloads call `onFailure` or `onPass`, respectively.
    /// - Parameters:
    ///   - request: The `RouterRequest` object used to get information about the request.
    ///   - response: The `RouterResponse` object used to respond to the request.
    ///   - onSuccess: The closure to invoke in the case of successful authentication.
    ///   - onFailure: The closure to invoke in the case of an authentication failure.
    ///   - onPass: The closure to invoke when the plugin doesn't recognize the authentication data (usually an
    ///       authentication token) in the request.
    private func accessTokenRequest(request: RouterRequest,
                            response: RouterResponse,
                            onSuccess: @escaping (UserProfile) -> Void,
                            onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                            onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void) {
        var requestOptions: [ClientRequest.Options] = [.schema("https://"),
                                                      .hostname("api.twitter.com"),
                                                      .method("POST"),
                                                      .path("oauth/access_token")]
        var headers = [String : String]()
        
        let nonce = String.nonce
        let timeStamp = Date().timeIntervalSince1970.roundedString
        
        var parameters = ["oauth_consumer_key" : consumerKey,
                          "oauth_nonce" : nonce,
                          "oauth_signature_method" : "HMAC-SHA1",
                          "oauth_timestamp" : timeStamp,
                          "oauth_token" : oAuthToken,
                          "oauth_version" : "1.0",
                          "oauth_verifier" : oAuthTokenVerifier]
    
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
                
                var responseDictionary = [String : String]()
                guard let fields = string?.components(separatedBy: "&") else {
                    Log.error("Twitter access token response not correct format: \(string)")
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
                        Log.error("Twitter access token response not correct format: \(string)")
                        onPass(accessTokenResponse.statusCode, .none)
                        return
                    }
                }
                
                guard let id = responseDictionary[userIDKey],
                    let displayName = responseDictionary[screenNameKey],
                    let newOAuthToken = responseDictionary[oAuthTokenKey],
                    let newOAuthTokenSecret = responseDictionary[oAuthTokenSecretKey] else {
                        Log.error("Twitter access token response did not contain user_id, screen_name, oauth_token, or oauth_token_secret.")
                        onPass(accessTokenResponse.statusCode, .none)
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
