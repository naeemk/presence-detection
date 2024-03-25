import asyncio

async def process_specific_data(data):
    # Process specific data here
    print("Processing specific data:", data)
    await asyncio.sleep(1)  # Simulate processing time

async def process_other_data(data):
    # Process other data here
    print("Processing other data:", data)
    await asyncio.sleep(0.5)  # Simulate processing time

async def receive_data():
    while True:
        # Simulate receiving data asynchronously
        await asyncio.sleep(0.2)
        data = await get_data_from_somewhere()  # Function to get data asynchronously
        if data == "specific":
            await process_specific_data(data)
        else:
            await process_other_data(data)

async def main():
    # Start receiving data asynchronously
    await receive_data()

asyncio.run(main())
