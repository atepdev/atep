# ATEP-R on ROS 2 (NOT run against a real ROS 2 install)

**Status, stated plainly.** ROS 2 is not installed on the machine this was written on. The message package has never been built with `colcon`, and the two rclpy nodes have never run. What was checked: `python3 -m py_compile` on every Python file, and a ROS-free unit test of the verification logic with a stub transport (5 tests, passing, using vectors from `../../vectors`). Treat the ROS wiring as a reviewed sketch until someone runs it on a ROS 2 distribution.

## What is here

| Path | Role |
| --- | --- |
| `atep_msgs/msg/Envelope.msg` | message: `uint8[] envelope` (the envelope bytes) plus untrusted metadata `command_class`, `sender_hint`, `suite` |
| `atep_msgs/package.xml`, `CMakeLists.txt` | standard `rosidl_default_generators` interface package |
| `atep_ros2_example/verifier.py` | `EnvelopeReceiver`: ROS-free verification using `atep_py` (32 lines) |
| `atep_ros2_example/nodes.py` | `EnvelopePublisher` and `EnvelopeSubscriber` rclpy nodes (38 lines) |
| `tests/test_verifier.py` | ROS-free tests with a stub bus |

The message carries the same envelope bytes as every other carrier. A receiver takes signer, class and payload from the verified result and ignores the metadata fields, except to compare `command_class` with the signed class. Topics follow `/fleet/<fleet>/<unit>/<class>`, the same convention as the MQTT example. The message type is DDS vendor neutral because it is plain ROS 2 IDL.

## Run the tests (works here)

```
cd examples/ros2
python3 -m unittest discover -s tests -v
python3 -m py_compile atep_ros2_example/*.py tests/*.py
```

The tests import `atep_py` from `../../python` (the independent pure Python implementation; it needs only the standard library and Python 3.8 or later). Cases: accepted, tampered, attestation not rooted in the verifier's roots (step 9), replay (step 6), mislabelled class.

## Use on ROS 2 (untested)

```
# in a colcon workspace src/ directory: link or copy atep_msgs, then
colcon build --packages-select atep_msgs
source install/setup.bash
export PYTHONPATH=/path/to/atep/python:/path/to/atep/examples/ros2:$PYTHONPATH
python3 - <<'PY'
from atep_ros2_example.verifier import EnvelopeReceiver
from atep_ros2_example.nodes import EnvelopeSubscriber, spin
rx = EnvelopeReceiver(recipient_seeds={...hex seeds...}, trust={"roots": ["atep:..."], "rules": []})
spin(EnvelopeSubscriber(rx, "f1", "u2", "telemetry"))
PY
```

The publisher node republishes envelope bytes made elsewhere, for example with the Rust CLI (`atep sign ... --command-class telemetry --attach ...` then `atep encrypt`). Signing inside a ROS node is deliberately not shown: key handling belongs to the robot's own key service.

## Limits

* The subscriber uses `verify_json` of `atep_py` with the vector policy format. Pure Python verification takes tens to hundreds of milliseconds per envelope (ML-DSA and ML-KEM in Python), which is too slow for high rate topics; use the Rust core through FFI or the C++ route for those.
* Not covered: sessions, group keys, DDS-Security interplay, QoS tuning, large messages (envelopes with inline attestations can reach tens of KB; check your DDS fragmentation settings).
* Revocation lists are not passed in; a real unit would add them and fail closed for motion, actuation, maintenance and non e-stop safety classes (spec section 17).
