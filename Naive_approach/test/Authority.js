const { expect } = require("chai");

describe("Authority contract", function () {
  it("Expect Auth create manf and give owner control to him", async function () {
    const [owner, manf1] = await ethers.getSigners();

    const Authority = await ethers.getContractFactory("AuthorityContract");

    const hardhatAuthority = await Authority.deploy();

    await hardhatAuthority.registerManufacturer(manf1.address,ethers.utils.formatBytes32String("STMICRO"));

    const mfcaddress= await hardhatAuthority.getManufacturerContractbyAddress(manf1.address);

    const Manufacturer = await ethers.getContractFactory("ManufacturerContract");
    
    const hardhatManufacturer = await Manufacturer.attach(mfcaddress);

    expect(await hardhatManufacturer.owner()).to.equal(manf1.address);
    
    //expect((await hardhatAuthority.getManufacturerRecord(manf1.address))[0]).to.equals(ethers.utils.formatBytes32String("STMICRO"));


  });
  
});
