//
//  File.swift
//  ProtoBuf
//
//  Created by mrJacob on 3/26/17.
//
//

import Foundation
import Kitura
import KituraNet
import Credentials
import LoggerAPI
import SwiftyJSON

/// If your client already has validated the user using Twitter's [“Log In With Twitter”](https://docs.fabric.io/apple/twitter/log-in-with-twitter.html),
/// you can pass in the token (`access_token`), token secret (`access_secret`), and token type (`X-token-type`) in the
/// request's headers. This will verify that the token is still valid and gather the user's information. This uses the 
/// Twitter REST API at https://dev.twitter.com/rest/reference/get/account/verify_credentials.
public class CredentialsTwitterVerify: CredentialsPluginProtocol {
    
    /// The name of the plugin.
    public var name: String {
        return "TwitterVerify"
    }
    
    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    /// An indication as to whether the plugin is redirecting or not.
    /// The redirecting scheme is used for web session authentication, where the users,
    /// that are not logged in, are redirected to a login page. All other types of
    /// authentication are non-redirecting, i.e., unauthorized requests are rejected.
    public var redirecting: Bool {
        return false
    }
    
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
        guard
            let requestType = request.headers["X-token-type"],
            requestType == self.name else {
                onPass(nil, nil)
                return
        }
        
        guard
            let token = request.headers["access_token"],
            let secret = request.headers["access_secret"] else {
                onFailure(nil ,nil)
                return
        }
        
        self.oAuthToken = token
        self.oAuthTokenSecret = secret
        
        verifyTwitterCredentials(request: request,
                                 response: response,
                                 onSuccess: onSuccess,
                                 onFailure: onFailure,
                                 onPass: onPass)
    }
    
    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate?
    
    //MARK Internal Plumbing
    
    //Twitter Response Keys
    let oAuthTokenKey = "oauth_token"
    let oAuthTokenSecretKey = "oauth_token_secret"
    private let userIDKey = "id_str"
    private let screenNameKey = "screen_name"
    
    /// You must register an app at https://apps.twitter.com in order to get the consumer key.
    let consumerKey: String
    
    /// You must register an app at https://apps.twitter.com in order to get the consumer secret.
    let consumerSecret: String
    
    private var oAuthToken: String = ""
    private var oAuthTokenSecret: String = ""
    
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
    
    /// The method gathers the necessary components to create a request to https://api.twitter.com/1.1/account/verify_credentials.json.
    /// At this point, a valid OAuth Token and OAuth Secret gathered by the client should be valid. If the request is
    /// successful, information about the user will be filled in and the delegate will be notified. Failure or incorrect
    /// payloads call `onFailure` or `onPass`, respectively.
    /// - Parameters:
    ///   - request: The `RouterRequest` object used to get information about the request.
    ///   - response: The `RouterResponse` object used to respond to the request.
    ///   - onSuccess: The closure to invoke in the case of successful authentication.
    ///   - onFailure: The closure to invoke in the case of an authentication failure.
    ///   - onPass: The closure to invoke when the plugin doesn't recognize the authentication data (usually an
    ///       authentication token) in the request.
    internal func verifyTwitterCredentials(request: RouterRequest,
                                           response: RouterResponse,
                                           onSuccess: @escaping (UserProfile) -> Void,
                                           onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                                           onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void) {
        
        var requestOptions: [ClientRequest.Options] = [.schema("https://"),
                                                       .hostname("api.twitter.com"),
                                                       .method("GET"),
                                                       .path("/1.1/account/verify_credentials.json")]
        var headers = [String : String]()
        
        let nonce = String.nonce
        let timeStamp = Date().timeIntervalSince1970.roundedString
        
        var parameters = ["oauth_consumer_key" : consumerKey,
                          "oauth_nonce" : nonce,
                          "oauth_signature_method" : "HMAC-SHA1",
                          "oauth_timestamp" : timeStamp,
                          "oauth_token" : oAuthToken,
                          "oauth_version" : "1.0"]
        
        let url = "https://api.twitter.com/1.1/account/verify_credentials.json"
        
        guard
            let signature = String.oAuthSignature(fromMethod: "GET",
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
            guard
                let accessTokenResponse = optionalResponse, accessTokenResponse.statusCode == .OK else {
                    Log.error("Twitter access token response returned with \(String(describing: optionalResponse?.statusCode))")
                    onFailure(optionalResponse?.statusCode, nil)
                    return
            }
            
            var body = Data()
            do {
                try accessTokenResponse.readAllData(into: &body)
                
                let json = JSON(data: body)
                
                guard
                    let id = json[self.userIDKey].string,
                    let displayName = json[self.screenNameKey].string else {
                        Log.error("Twitter reauthorization response did not contain id_str, screen_name.")
                        onPass(accessTokenResponse.statusCode, .none)
                        return
                }
                
                let user = UserProfile(id: id,
                                       displayName: displayName,
                                       provider: self.name)
                self.userProfileDelegate?.update(userProfile: user, from: json.dictionaryValue)
                onSuccess(user)
            }
            catch TwitterResponseError.dataNotString {
                Log.error("Twitter token response body data could not be converted to String.")
                onPass(optionalResponse?.statusCode, nil)
            }
            catch TwitterResponseError.noQueryComponents(let string) {
                Log.error("Twitter token response body did not have query components. String: \(string)")
                onPass(optionalResponse?.statusCode, nil)
            }
            catch TwitterResponseError.noKeyValuePairs(let string) {
                Log.error("Twitter token response body did not have keys or values. String: \(string)")
                onPass(optionalResponse?.statusCode, nil)
            }
            catch {
                Log.error("Twitter token response body data not valid.")
                onPass(optionalResponse?.statusCode, nil)
            }
        }
        
        twitterRequest.end()
    }
}
