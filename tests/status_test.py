import unittest,asyncio
from status import Status

Status.bootstrap()

class TestStatus(unittest.TestCase):

    def test_canary(self):
        self.assertTrue(True)

    def test_retention_more_than0(self):
        self.assertTrue(Status.get_max_retention_hours() > 0)



class TestStatusAsync(unittest.IsolatedAsyncioTestCase):

    __bucket = 0

    @staticmethod
    def bucket_gen():
        TestStatusAsync.__bucket += 1
        return TestStatusAsync.__bucket

    async def test_preserves_less_than_retention(self):
        Status.set_bucket_gen_method(TestStatusAsync.bucket_gen)

        max = Status.get_max_retention_hours() - 1

        for x in range(0, max):
            await Status.report('A', 'B', x)

        report = await Status.get()

        self.assertEqual (max, len(report['status']['A']['B'].keys()))


    async def test_preserves_only_retention(self):
        Status.set_bucket_gen_method(TestStatusAsync.bucket_gen)
        
        max = Status.get_max_retention_hours() + 10

        for x in range(0, max):
            await Status.report('A', 'B', x)

        report = await Status.get()

        self.assertEqual (Status.get_max_retention_hours(), len(report['status']['A']['B'].keys()))


if __name__ == '__main__':
    unittest.main()

