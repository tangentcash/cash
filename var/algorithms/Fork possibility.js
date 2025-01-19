let committeeSize = 24;
for (let priority = 0; priority < committeeSize; priority++) {
    console.log({
        priority: priority,
        possibility: Math.max(1 - Math.pow(1 - priority / committeeSize, 4), 0.0001)
    });
}