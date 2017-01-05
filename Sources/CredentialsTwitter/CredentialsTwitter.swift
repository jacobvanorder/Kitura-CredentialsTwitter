/**
 * Copyright IBM Corporation 2017
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
import Cryptor

import SwiftyJSON

import Foundation

public class CredentialsTwitter: CredentialsPluginProtocol {
    
    let consumerKey: String
    let consumerSecret: String
    let callbackUrl: String
    let options: [String: Any]?
    
    private var oAuthToken: String = ""
    private var oAuthTokenSecret: String = ""
    
    private var hasOAuthToken: Bool {
        return oAuthToken.isEmpty
    }
    
    //consumerKey
    //consumerSecret
    
    public init(consumerKey: String,
                consumerSecret: String,
                callbackUrl: String,
                options: [String: Any]?=nil) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.callbackUrl = callbackUrl
        self.options = options
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
        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("api.twitter.com"))
        requestOptions.append(.method("POST"))
        requestOptions.append(.path("oauth/request_token"))
        var headers = [String: String]()
        var parameters = [String:String]()
        
        let nonce = String.nonce
        let timeStamp = String(Int(Date().timeIntervalSince1970))
        
        parameters["oauth_consumer_key"] = consumerKey
        parameters["oauth_signature_method"] = "HMAC-SHA1"
        parameters["oauth_timestamp"] = timeStamp
        parameters["oauth_nonce"] = nonce
        parameters["oauth_version"] = "1.0"
        
        let signature = String.oAuthSignature(fromMethod: "POST",
                                              url: "https://api.twitter.com/oauth/request_token",
                                              parameters: parameters,
                                              with: consumerSecret)!
        parameters["oauth_signature"] = signature
        
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\(value)")
        }
        headers["Authorization"] = "OAuth " + keyValues.joined(separator: ",")
        requestOptions.append(.headers(headers))
        
        let twitterRequest = HTTP.request(requestOptions) {
            (optionalResponse) in
            guard let response = optionalResponse, response.statusCode == HTTPStatusCode.OK else {
                //Fail
                return
            }
            
            var body = Data()
            do {
                try response.readAllData(into: &body)
                let string = String(data: body, encoding: String.Encoding.utf8)
                let fields = string?.components(separatedBy: "&")
                var responseDictionary = [String: String]()
                for field in fields! {
                    let keyValue = field.components(separatedBy: "=")
                    responseDictionary[keyValue.first!] = keyValue.last!
                }
                
                guard let token = responseDictionary["oauth_token"],
                    let secret = responseDictionary["oauth_token_secret"] else {
                        //Fail
                        return
                }
                
                self.oAuthToken = token
                self.oAuthTokenSecret = secret
                
                
            }
            catch {
                //Fail
            }
            
        }
        
        twitterRequest.end()
    }
}

extension CharacterSet {
    static var twitterParameterStringSet: CharacterSet {
        var alphaNumericSet: CharacterSet = .alphanumerics
        alphaNumericSet.insert(charactersIn: "_-.~") //https://dev.twitter.com/oauth/overview/percent-encoding-parameters
        return alphaNumericSet
    }
}

extension String {
    static var nonce: String {
        return UUID().uuidString.components(separatedBy: "-").first!
    }
    
    //https://dev.twitter.com/oauth/overview/creating-signatures
    static func oAuthSignature(fromMethod method: String, url: String, parameters: [String:String], with consumerSecret: String) -> String? {
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\(value.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!)")
        }
        let sortedParameters = keyValues.sorted(by: {$0 < $1})
        let joinedParameters = sortedParameters.joined(separator: "&")
        guard let percentEncodedUrl = url.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet),
            let percentEncodedJoinedParameters = joinedParameters.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet) else {
                return nil
        }
        
        
        //join method, percent-encoded url, percent-encoded parameters
        let rawString = [method, percentEncodedUrl, percentEncodedJoinedParameters].joined(separator: "&")
        
        let hmac = HMAC(using: .sha1, key: consumerSecret.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)! + "&")
        let encryptedKey = hmac.update(string: rawString)!
        let encodedRawBytes = encryptedKey.final()
        let encodedData = Data(bytes: encodedRawBytes)
        let encodedString = encodedData.base64EncodedString()
        return encodedString.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!
    }
}
