import 'package:jwt_serializer/jwt_serializer.dart';
import 'package:test/test.dart';

DateTime dateTime(int time) => DateTime.fromMillisecondsSinceEpoch(time * 1000);

void main() {
  group('JwtSerializer tests', () {
    const validToken = 'eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyM2U0NTY3LWU4OWItMjNkNC1hMDY2LTQ1Njc2NTk3ODExMSIsImNvbXBhbnlfaWQiOiIxYzg4MTZhNy01ZDNkLTRhMzktYjVmOS02ZjM0NDZlM2I4MWEiLCJsZXZlbCI6IkFkbWluIiwiZXhwaXJlX2F0IjoxNzE1Nzc3ODYzfQ.N_oKYwAwPwGQDNFpkT7UxZtNDxxBUKng-7AfAjyzYKY'; // Reemplaza con un JWT válido para tus pruebas
    const invalidToken = 'invalid.token.string';
    const expiredToken = 'eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyM2U0NTY3LWU4OWItMjNkNC1hMDY2LTQ1Njc2NTk3ODExMSIsImNvbXBhbnlfaWQiOiIxYzg4MTZhNy01ZDNkLTRhMzktYjVmOS02ZjM0NDZlM2I4MWEiLCJsZXZlbCI6IkFkbWluIiwiZXhwaXJlX2F0IjoxNjUxNDA5MDkzfQ.CD99OJP5P1PdxcecT5F_4iJTOByitT6AF4nOWluITJk'; // Reemplaza con un JWT expirado para tus pruebas

    test('Decode valid JWT token', () {
      final decoded = JwtSerializer.decode(validToken);
      expect(decoded, isA<Map<String, dynamic>>());
      expect(decoded['expire_at'], isNotNull);
    });

    test('Decode invalid JWT token throws FormatException', () {
      expect(() => JwtSerializer.decode(invalidToken), throwsFormatException);
    });

    test('tryDecode with valid JWT token returns decoded payload', () {
      final decoded = JwtSerializer.tryDecode(validToken);
      expect(decoded, isNotNull);
      expect(decoded, isA<Map<String, dynamic>>());
    });

    test('tryDecode with invalid JWT token returns null', () {
      final decoded = JwtSerializer.tryDecode(invalidToken);
      expect(decoded, isNull);
    });


    test('isExpired with expired JWT token returns true', () {
      final isExpired = JwtSerializer.isExpired(expiredToken);
      expect(isExpired, isTrue);
    });

    test('getExpirationDate returns correct date', () {
      final expirationDate = JwtSerializer.getExpirationDate(validToken);
      expect(expirationDate, isA<DateTime>());
    });


    test('getRemainingTime returns correct duration', () {
      final remainingTime = JwtSerializer.getRemainingTime(validToken);
      expect(remainingTime, isA<Duration>());
    });

    test('getRemainingTime for expired token returns negative duration', () {
      final remainingTime = JwtSerializer.getRemainingTime(expiredToken);
      expect(remainingTime, isNotNull);
      expect(remainingTime!.isNegative, isTrue);
    });
  });
}
