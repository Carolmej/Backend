export default (error, res) => {
    let errorDate = new Date().toLocaleString("en-GB", { timeZone: "CST", hour12: true });
    console.log(errorDate + ' | ' + error);
    return res.status(500).json({ 
        message: 'Internal server error at time: ' + errorDate
    });
}