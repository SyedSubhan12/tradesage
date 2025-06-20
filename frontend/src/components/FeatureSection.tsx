import React from 'react';

const FeatureSection = () => {
  return (
    <section className="py-20">
      <h2 className="text-3xl font-bold text-center">Features</h2>
      <div className="container mx-auto grid grid-cols-1 md:grid-cols-3 gap-8 mt-8">
        {/* Placeholder for Feature Cards */}
        <div className="border p-4 rounded-lg">Feature 1</div>
        <div className="border p-4 rounded-lg">Feature 2</div>
        <div className="border p-4 rounded-lg">Feature 3</div>
      </div>
    </section>
  );
};

export default FeatureSection;
