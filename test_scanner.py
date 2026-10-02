import unittest
from scanner import audit

class ScannerTests(unittest.TestCase):
    def test_security_cases(self):
        self.assertEqual(len(audit({"planned_values":{"root_module":{"resources":[{"address":"aws_db_instance.x","type":"aws_db_instance","values":{"publicly_accessible":True,"storage_encrypted":False}}]}}})), 2)
        self.assertEqual(audit({"planned_values":{"root_module":{"resources":[{"address":"aws_ebs_volume.x","type":"aws_ebs_volume","values":{"encrypted":True}}]}}}), [])
        self.assertEqual(audit({"planned_values":{"root_module":{"child_modules":[{"resources":[{"address":"module.x.aws_ebs_volume.x","type":"aws_ebs_volume","values":{}}]}]}}})[0]["severity"], "UNKNOWN")

if __name__ == "__main__":
    unittest.main()

