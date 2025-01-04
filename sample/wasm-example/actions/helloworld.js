
async function helloworld() {
    console.log(helloworldwasm, data);
    try {
    const greeting = helloworldwasm.callFunction("greet_name", data.name).expect('string');
    console.log(greeting);
    alert(greeting);
    } catch (e) {
        console.error(e);
    }
}

helloworld();