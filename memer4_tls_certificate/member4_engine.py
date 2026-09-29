from tls_analyzer import TLSAnalyzer
from certificate_analyzer import CertificateAnalyzer


class Member4Engine:

    def __init__(self):
        self.tls_analyzer = TLSAnalyzer()
        self.certificate_analyzer = CertificateAnalyzer()

    def analyze(self, data):

        tls_data = data.get("tls", {})
        certificate_data = data.get("certificate", {})

        # Analyze TLS information
        tls_result = self.tls_analyzer.analyze(tls_data)

        # Analyze certificate information
        certificate_result = self.certificate_analyzer.analyze(
            certificate_data
        )

        # Combine findings
        findings = []

        findings.extend(tls_result.get("findings", []))
        findings.extend(certificate_result.get("findings", []))

        # Final Member 4 output
        result = {
            "module": "Member 4 - TLS & Certificate Analysis",

            "tls_analysis": tls_result,

            "certificate_analysis": certificate_result,

            "findings": findings
        }

        return result