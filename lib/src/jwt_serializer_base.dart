import 'dart:convert';

class JwtSerializer {
  /// Decodes a JWT token into a `Map<String, dynamic>` containing the decoded JSON payload.
  /// Throws [FormatException] if the token is not a valid JWT token.
  static Map<String, dynamic> decode(String token) {
    final splitToken = token.split(".");
    if (splitToken.length != 3) {
      throw FormatException('Invalid token: Incorrect number of segments');
    }
    try {
      final payloadBase64 = splitToken[1];
      final normalizedPayload = base64.normalize(payloadBase64);
      final payloadString = utf8.decode(base64.decode(normalizedPayload));
      final decodedPayload = jsonDecode(payloadString);

      if (decodedPayload is! Map<String, dynamic>) {
        throw FormatException('Invalid payload: Not a JSON object');
      }

      return decodedPayload;
    } catch (error) {
      throw FormatException('Invalid payload: ${error.toString()}');
    }
  }

  /// Decodes a JWT token into a `Map<String, dynamic>` containing the decoded JSON payload.
  /// Returns null if the token is not valid.
  static Map<String, dynamic>? tryDecode(String token) {
    try {
      return decode(token);
    } catch (e) {
      return null;
    }
  }

  /// Checks if a token is expired.
  /// Returns false if the token is valid, true if it is expired.
  /// Throws [FormatException] if the token is not a valid JWT token.
  static bool isExpired(String token) {
    final expirationDate = getExpirationDate(token);
    if (expirationDate == null) {
      return false;
    }
    return DateTime.now().isAfter(expirationDate);
  }

  static DateTime? _getDate({required String token, required String claim}) {
    final decodedToken = decode(token);
    final claimValue = decodedToken[claim] as int?;
    if (claimValue == null) {
      return null;
    }
    return DateTime.fromMillisecondsSinceEpoch(claimValue * 1000);
  }

  /// Returns the token's expiration date.
  /// Throws [FormatException] if the token is not a valid JWT token.
  static DateTime? getExpirationDate(String token) {
    return _getDate(token: token, claim: 'expire_at');
  }

  /// Returns the token's issuing date (iat).
  /// Throws [FormatException] if the token is not a valid JWT token.
  static Duration? getTokenTime(String token) {
    final issuedAtDate = _getDate(token: token, claim: 'iat');
    if (issuedAtDate == null) {
      return null;
    }
    return DateTime.now().difference(issuedAtDate);
  }

  /// Returns the remaining time until the token's expiration date.
  /// Throws [FormatException] if the token is not a valid JWT token.
  static Duration? getRemainingTime(String token) {
    final expirationDate = getExpirationDate(token);
    if (expirationDate == null) {
      return null;
    }
    return expirationDate.difference(DateTime.now());
  }
}
