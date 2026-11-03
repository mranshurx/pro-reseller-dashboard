const PANELS = [
  {
    id: 'phantom', name: 'Phantom Webmode', tag: 'PHANTOM',
    plans: [
      { id: '1h',  label: '1 HOUR',   price: 7,   hours: 1  },
      { id: '3h',  label: '3 HOURS',  price: 12,  hours: 3  },
      { id: '6h',  label: '6 HOURS',  price: 18,  hours: 6  },
      { id: '24h', label: '24 HOURS', price: 44,  hours: 24 },
      { id: '7d',  label: '7 DAYS',   price: 165, hours: 168 },
      { id: '30d', label: '30 DAYS',  price: 299, hours: 720 }
    ]
  },
  {
    id: 'myth', name: 'Myth Webmode', tag: 'MYTH',
    plans: [
      { id: '1h',  label: '1 HOUR',   price: 6,  hours: 1  },
      { id: '3h',  label: '3 HOURS',  price: 8,  hours: 3  },
      { id: '6h',  label: '6 HOURS',  price: 16, hours: 6  },
      { id: '12h', label: '12 HOURS', price: 25, hours: 12 },
      { id: '1d',  label: '1 DAY',    price: 32, hours: 24 },
      { id: '3d',  label: '3 DAYS',   price: 37, hours: 72 }
    ]
  },
  {
    id: 'xreg', name: 'XReg Webmode', tag: 'XREG',
    plans: [
      { id: '1h',  label: '1 HOUR',   price: 7,   hours: 1  },
      { id: '3h',  label: '3 HOURS',  price: 13,  hours: 3  },
      { id: '6h',  label: '6 HOURS',  price: 18,  hours: 6  },
      { id: '12h', label: '12 HOURS', price: 38,  hours: 12 },
      { id: '24h', label: '24 HOURS', price: 43,  hours: 24 },
      { id: '7d',  label: '7 DAYS',   price: 170, hours: 168 },
      { id: '30d', label: '30 DAYS',  price: 300, hours: 720 }
    ]
  },
  {
    id: 'drip', name: 'Drip Wire Externel', tag: 'DRIP',
    plans: [
      { id: '6h',  label: '6 HOURS',  price: 18,  hours: 6  },
      { id: '12h', label: '12 HOURS', price: 40,  hours: 12 },
      { id: '1d',  label: '1 DAY',    price: 45,  hours: 24 },
      { id: '7d',  label: '7 DAYS',   price: 170, hours: 168 }
    ]
  }
];

function findPlan(panelId, planId) {
  const panel = PANELS.find(p => p.id === panelId);
  if (!panel) return null;
  const plan = panel.plans.find(x => x.id === planId);
  if (!plan) return null;
  return { ...plan, panelId: panel.id, panelName: panel.name };
}

module.exports = { PANELS, findPlan };
