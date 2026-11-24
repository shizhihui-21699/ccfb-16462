# Test support namespace kept for compatibility; the simulator now lives in
# lib so the demo can use it too.
module DomainGuard
  module TestSupport
    FakeDns = SimulatedDns
  end
end
