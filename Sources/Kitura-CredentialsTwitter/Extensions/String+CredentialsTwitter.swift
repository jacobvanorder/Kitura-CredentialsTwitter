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

import Foundation

import Cryptor

public extension String {
    static var nonce: String {
        return UUID().uuidString.components(separatedBy: "-").first!
    }
    
    static func oAuthAuthorizationString(fromParameters parameters: [String: String]) -> String {
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\"\(value)\"")
        }
        return "OAuth " + keyValues.sorted().joined(separator: ",")
    }
    
    /// Twitter OAuth requires that within the OAuth string, an entry for the oauth_signature is entered.
    /// This signature is comprised of a base string that is the HTTP method (e.g., POST, GET, etc…), the
    /// percent-encoded URL of the destination, and the parameters which are joined by an equals and chained
    /// together with an ampersand which is finally percent encoded. This base string is then encoded by a
    /// string comprised of the percent-encoded consumer secret (found on your Twitter application's page), an
    /// ampersand, and your oAuth Token. If you don't have an oAuth Token at this point, you still need the
    /// joining ampersand but followed by a blank. These two strings are encoded using HMAC-SHA1. The return
    /// value is that data transformed into a base 64-encoded string which is percent-encoded itself. Simple!
    /// For more info: https://dev.twitter.com/oauth/overview/creating-signatures
    ///
    /// - Parameters:
    ///   - method: The HTTP method for the resulting call you intend to make.
    ///   - urlString: The URL of the resulting call you intend to make.
    ///   - parameters: The OAuth and non-OAuth parameters you intend to send in the resulting call.
    ///   - consumerSecret: The consumer secret you get from Twitter on your application's page.
    ///   - oAuthToken: The optional OAuth Token you received in previous calls.
    /// - Returns: A percent-encoded string which will be added as a parameter as `oauth_signature`.
    static func oAuthSignature(fromMethod method: String,
                               urlString: String,
                               parameters: [String:String],
                               consumerSecret: String,
                               oAuthToken: String = "") -> String? {
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\(value.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!)")
        }
        let sortedParameters = keyValues.sorted(by: <)
        let joinedParameters = sortedParameters.joined(separator: "&")
        guard let percentEncodedUrl = urlString.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet),
            let percentEncodedJoinedParameters = joinedParameters.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet),
            let percentEncodedConsumerSecret = consumerSecret.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet) else {
                return nil
        }
        
        let rawString = [method, percentEncodedUrl, percentEncodedJoinedParameters].joined(separator: "&")
        
        let hmac = HMAC(using: .sha1, key: percentEncodedConsumerSecret + "&" + oAuthToken)
        let encryptedKey = hmac.update(string: rawString)!
        let encodedRawBytes = encryptedKey.final()
        let encodedData = Data(bytes: encodedRawBytes)
        let encodedString = encodedData.base64EncodedString()
        return encodedString.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!
    }
}
