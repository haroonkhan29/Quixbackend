const mongoose = require('mongoose');

const Expensesheetform = mongoose.model('Expensesheetform', {
   employeesCost: String,
   jans: String,
      febs:  String,
      marchs: String,
      aprils: String,
      mays:  String,
      junes: String,
      julys:  String,
      augs:  String,
      seps:  String,
      octs: String,
      novs:  String,
      decs:  String,
    officesCost:  String,
    officesjan:  String,
    officesfeb:  String,
    officesmarch:  String,
    officesapril:  String,
    officesmay:  String,
    officesjune:  String,
    officesjuly:  String,
    officesaug:  String,
    officessep:  String,
    officesoct:  String,
    officesnov:  String,
    officesdec:  String,
    marketingsCost:  String,	
    marketingsjan:  String,
    marketingsfeb:  String,
    marketingsmarch:  String,
    marketingsapril:  String,
    marketingsmay:  String,
    marketingsjune:  String,
    marketingsjuly:  String,
    marketingsaug:  String,
    marketingssep:  String,
    marketingsoct:  String,
    marketingsnov:  String,
    marketingsdec:  String,
    eventss:  String,	
    eventssjan:  String,
    eventssfeb:  String,
    eventssmarch:  String,
    eventssapril:  String,
    eventssmay:  String,
    eventssjune:  String,
    eventssjuly:  String,
    eventssaug:  String,
    eventsssep:  String,
    eventssoct:  String,
    eventssnov:  String,
    eventssdec:  String,
});

module.exports = Expensesheetform;
