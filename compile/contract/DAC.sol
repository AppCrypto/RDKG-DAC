// SPDX-License-Identifier: UNLICENSED
//pragma experimental ABIEncoderV2;
pragma solidity ^0.8.0;

contract DAC {

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    struct Commitment {
        bytes[] C;         // HashC commitments
        bytes[] CPrime;    // HashC' commitments
        uint256[] RCoeffs; // r(X) coefficients
    }

    // 保存 h' (G1Point) -> nu (G1Point) 的映射
    mapping(bytes32 => G1Point) internal hPrimeToNu;

    // DAO 成员的 com 提交：coms[memberIndex][qIndex][tIndex] = G2Point
    mapping(uint256 => mapping(uint256 => mapping(uint256 => G2Point))) private coms;

    // DAO 成员的 PK 提交：pks[memberIndex][qIndex] = G2Point
    mapping(uint256 => mapping(uint256 => G2Point)) private member_PK;

    bool PKResult;

    mapping(uint256 => Commitment) private commitments;


    /// @notice 上传成员编号为 id 的 commitment（C, CPrime, RCoeffs）
    function uploadCommitment(
        uint256 id,
        bytes[] calldata C,
        bytes[] calldata CPrime,
        uint256[] calldata RCoeffs
    ) external {
        require(C.length > 0 && C.length == CPrime.length, "Invalid commitment array lengths");
        commitments[id] = Commitment({
            C: C,
            CPrime: CPrime,
            RCoeffs: RCoeffs
        });
    }

    /// @notice 查询成员编号为 id 的 commitment
    function getCommitment(uint256 id)
    external
    view
    returns (bytes[] memory, bytes[] memory, uint256[] memory)
    {
        Commitment storage c = commitments[id];
        return (c.C, c.CPrime, c.RCoeffs);
    }

    // 上传函数：一次性上传一个成员的全部 [q+1][t] G2Points
    function uploadComs(
        uint256 memberIndex,
        uint256 qPlus1,
        uint256 t,
        uint256[4][] calldata flatPoints  // 每个点用 [X0, X1, Y0, Y1] 表示
    ) external {
        require(flatPoints.length == qPlus1 * t, "Invalid length");

        uint256 counter = 0;
        for (uint256 i = 0; i < qPlus1; i++) {
            for (uint256 j = 0; j < t; j++) {
                uint256[4] memory pt = flatPoints[counter++];
                coms[memberIndex][i][j] = G2Point(
                    [pt[0], pt[1]],
                    [pt[2], pt[3]]
                );
            }
        }
    }

    function hashH(uint256 id, uint256 order) public view returns (uint256) {
        Commitment storage c = commitments[id];

        bytes memory allBytes;

        for (uint i = 0; i < c.C.length; i++) {
            allBytes = bytes.concat(allBytes, c.C[i]);
        }

        for (uint i = 0; i < c.CPrime.length; i++) {
            allBytes = bytes.concat(allBytes, c.CPrime[i]);
        }

        bytes32 digest = sha256(allBytes);
        return uint256(digest) % order;
    }

    function testHashH(uint256 id, uint256 order) public returns (uint256) {
        return hashH(id, order); // 触发实际 Gas 消耗
    }


    // 上传函数：一次性上传一个成员的全部PK [q+1] G2Points
    function uploadPK(
        uint256 memberIndex,
        uint256 q,
        G2Point memory PK
    ) external {
        member_PK[memberIndex][q] = G2Point(
            [PK.X[0], PK.X[1]],
            [PK.Y[0], PK.Y[1]]
        );
    }


    // 上传一个 (h', nu) 对
    function uploadHPrimeNu(G1Point memory hPrime, G1Point memory nu) public {
        bytes32 key = hashG1Point(hPrime);
        hPrimeToNu[key] = nu;
    }


    // 查询某个 h' 是否存在，如果存在，返回对应的 nu
    function queryNuByHPrime(G1Point memory hPrime) public view returns (bool found, G1Point memory nu) {
        bytes32 key = hashG1Point(hPrime);
        G1Point memory stored = hPrimeToNu[key];
        if (stored.X == 0 && stored.Y == 0) {
            return (false, G1Point(0, 0));
        }
        return (true, stored);
    }

    // 辅助：将 G1 点打包后 hash
    function hashG1Point(G1Point memory p) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(p.X, p.Y));
    }

    // 内部函数：返回 a + b 的 G2Point 和
    function _G2Add(
        G2Point memory a,
        G2Point memory b
    ) internal view returns (G2Point memory) {
        (uint256 x1, uint256 x0, uint256 y1, uint256 y0) = ECTwistAdd(
            a.X[1], a.X[0],
            a.Y[1], a.Y[0],
            b.X[1], b.X[0],
            b.Y[1], b.Y[0]
        );

        return G2Point([x0, x1], [y0, y1]);
    }


    // 公共测试接口：判断 a + b 是否等于 c
    function testG2Add(
        G2Point memory a,
        G2Point memory b,
        G2Point memory c
    ) public view returns (bool) {
        (uint256 x1, uint256 x0, uint256 y1, uint256 y0) = ECTwistAdd(
            a.X[1], a.X[0],
            a.Y[1], a.Y[0],
            b.X[1], b.X[0],
            b.Y[1], b.Y[0]
        );

        G2Point memory sum = G2Point([x0, x1], [y0, y1]);
        return equals2(sum, c);
    }

    function aggregateAllComs(
        uint256 n,
        uint256 qPlus1,
        uint256 t
    ) external {
        require(n > 0, "Invalid number of members");

        for (uint256 q = 0; q < qPlus1; q++) {
            for (uint256 j = 0; j < t; j++) {
                // 初始化为第一个成员（索引 1）的点
                G2Point memory result = coms[1][q][j];

                // 从成员 2 到 n 累加
                for (uint256 i = 2; i <= n; i++) {
                    result = _G2Add(result, coms[i][q][j]);
                }

                // 存入成员索引 0
                coms[0][q][j] = result;
            }
        }
    }

    function getComPoint(uint256 memberIndex, uint256 i, uint256 j) external view returns (G2Point memory) {
        G2Point memory pt = coms[memberIndex][i][j];
        return pt;
    }


    function verifySingleShare(
        uint256 index,           // 成员索引 i
        uint256 qIndex,          // 属性索引 q
        uint256 t,               // 阈值 t（com 的长度）
        G2Point memory share     // 成员的 AX 或 BY[j-1]
    ) public {
        require(t > 0, "threshold t must be > 0");

        // 初始值：com[0]，即 user=0, q=qIndex, j=0
        G2Point memory right = coms[0][qIndex][0];

        uint256 x = index + 1;
        uint256 power;

        for (uint256 j = 1; j < t; j++) {
            power = expMod(x, j, GEN_ORDER);

            G2Point memory term = coms[0][qIndex][j];

            (uint256 xy, uint256 xx, uint256 yy, uint256 yx) = ECTwistMul(
                power,
                term.X[1], term.X[0],
                term.Y[1], term.Y[0]
            );

            term = G2Point([xx, xy], [yx, yy]);

            (xy, xx, yy, yx) = ECTwistAdd(
                right.X[1], right.X[0],
                right.Y[1], right.Y[0],
                term.X[1], term.X[0],
                term.Y[1], term.Y[0]
            );

            right = G2Point([xx, xy], [yx, yy]);
        }
        PKResult = equals2(share, right);
    }

    function GetPKResult() public view returns (bool) {
        return PKResult;
    }


    // p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

    // (P+1) / 4
    function A() pure internal returns (uint256) {
        return CURVE_A;
    }

    function N() pure internal returns (uint256) {
        return GEN_ORDER;
    }

    /// return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    G1Point G1 = G1Point(1, 2);
    G2Point G2 = G2Point(
        [11559732032986387107991004021392285783925812861821192530917403151452391805634,
        10857046999023057135944570762232829481370756359578518086990519993285655852781],
        [4082367875863433681332203403145435568316851327593401208105741076214120093531,
        8495653923123431417604973247489272438418190587263600148770280649306958101930]
    );

    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
    internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
        return output[0];
    }


    /// return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }

    /// return the sum of two points of G1
    function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
    }

    /// return the product of a point on G1 and a scalar, i.e.
    /// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function g1mul(G1Point memory p, uint256 s) view internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require (success);
    }

    function g1neg(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    /// return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }


    /// Convenience method for a pairing check for two pairs.
//	function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
//		G1Point[] memory p1 = new G1Point[](2);
//		G2Point[] memory p2 = new G2Point[](2);
//		p1[0] = a1;
//		p1[1] = b1;
//		p2[0] = a2;
//		p2[1] = b2;
//		return pairing(p1, p2);
//	}

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) view internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }

    uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 internal constant TWISTBX = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 internal constant TWISTBY = 0x9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2;
    uint internal constant PTXX = 0;
    uint internal constant PTXY = 1;
    uint internal constant PTYX = 2;
    uint internal constant PTYY = 3;
    uint internal constant PTZX = 4;
    uint internal constant PTZY = 5;

    /**
     * @notice Add two twist points
     * @param pt1xx Coefficient 1 of x on point 1
     * @param pt1xy Coefficient 2 of x on point 1
     * @param pt1yx Coefficient 1 of y on point 1
     * @param pt1yy Coefficient 2 of y on point 1
     * @param pt2xx Coefficient 1 of x on point 2
     * @param pt2xy Coefficient 2 of x on point 2
     * @param pt2yx Coefficient 1 of y on point 2
     * @param pt2yy Coefficient 2 of y on point 2
     * @return (pt3xx, pt3xy, pt3yx, pt3yy)
     */
    function ECTwistAdd(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy
    ) public view returns (
        uint256, uint256,
        uint256, uint256
    ) {
        if (
            pt1xx == 0 && pt1xy == 0 &&
            pt1yx == 0 && pt1yy == 0
        ) {
            if (!(
                pt2xx == 0 && pt2xy == 0 &&
                pt2yx == 0 && pt2yy == 0
            )) {
                assert(_isOnCurve(
                    pt2xx, pt2xy,
                    pt2yx, pt2yy
                ));
            }
            return (
                pt2xx, pt2xy,
                pt2yx, pt2yy
            );
        } else if (
            pt2xx == 0 && pt2xy == 0 &&
            pt2yx == 0 && pt2yy == 0
        ) {
            assert(_isOnCurve(
                pt1xx, pt1xy,
                pt1yx, pt1yy
            ));
            return (
                pt1xx, pt1xy,
                pt1yx, pt1yy
            );
        }

        assert(_isOnCurve(
            pt1xx, pt1xy,
            pt1yx, pt1yy
        ));
        assert(_isOnCurve(
            pt2xx, pt2xy,
            pt2yx, pt2yy
        ));

        uint256[6] memory pt3 = _ECTwistAddJacobian(
            pt1xx, pt1xy,
            pt1yx, pt1yy,
            1,     0,
            pt2xx, pt2xy,
            pt2yx, pt2yy,
            1,     0
        );

        return _fromJacobian(
            pt3[PTXX], pt3[PTXY],
            pt3[PTYX], pt3[PTYY],
            pt3[PTZX], pt3[PTZY]
        );
    }

    /**
     * @notice Multiply a twist point by a scalar
     * @param s     Scalar to multiply by
     * @param pt1xx Coefficient 1 of x
     * @param pt1xy Coefficient 2 of x
     * @param pt1yx Coefficient 1 of y
     * @param pt1yy Coefficient 2 of y
     * @return (pt2xx, pt2xy, pt2yx, pt2yy)
     */
    function ECTwistMul(
        uint256 s,
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy
    ) public view returns (
        uint256, uint256,
        uint256, uint256
    ) {
        uint256 pt1zx = 1;
        if (
            pt1xx == 0 && pt1xy == 0 &&
            pt1yx == 0 && pt1yy == 0
        ) {
            pt1xx = 1;
            pt1yx = 1;
            pt1zx = 0;
        } else {
            assert(_isOnCurve(
                pt1xx, pt1xy,
                pt1yx, pt1yy
            ));
        }

        uint256[6] memory pt2 = _ECTwistMulJacobian(
            s,
            pt1xx, pt1xy,
            pt1yx, pt1yy,
            pt1zx, 0
        );

        return _fromJacobian(
            pt2[PTXX], pt2[PTXY],
            pt2[PTYX], pt2[PTYY],
            pt2[PTZX], pt2[PTZY]
        );
    }

    function ECTwistNeg(uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy) pure internal returns (uint256, uint256,uint256, uint256) {
        // The prime q in the base field F_q for G2
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (pt1xx == 0 && pt1xy == 0 && pt1yx == 0 && pt1yy == 0)
            return (0, 0, 0, 0);
        return (pt1xx,pt1xy, q - (pt1yx % q), q - (pt1yy % q));
    }

    /**
     * @notice Get the field modulus
     * @return The field modulus
     */
    function GetFieldModulus() public pure returns (uint256) {
        return FIELD_MODULUS;
    }

    function submod2(uint256 a, uint256 b, uint256 n) internal pure returns (uint256) {
        return addmod(a, n - b, n);
    }

    function _FQ2Mul(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256, uint256) {
        return (
            submod2(mulmod(xx, yx, FIELD_MODULUS), mulmod(xy, yy, FIELD_MODULUS), FIELD_MODULUS),
            addmod(mulmod(xx, yy, FIELD_MODULUS), mulmod(xy, yx, FIELD_MODULUS), FIELD_MODULUS)
        );
    }

    function _FQ2Muc(
        uint256 xx, uint256 xy,
        uint256 c
    ) internal pure returns (uint256, uint256) {
        return (
            mulmod(xx, c, FIELD_MODULUS),
            mulmod(xy, c, FIELD_MODULUS)
        );
    }

    function _FQ2Add(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256, uint256) {
        return (
            addmod(xx, yx, FIELD_MODULUS),
            addmod(xy, yy, FIELD_MODULUS)
        );
    }

    function _FQ2Sub(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256 rx, uint256 ry) {
        return (
            submod2(xx, yx, FIELD_MODULUS),
            submod2(xy, yy, FIELD_MODULUS)
        );
    }

    function _FQ2Div(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal view returns (uint256, uint256) {
        (yx, yy) = _FQ2Inv(yx, yy);
        return _FQ2Mul(xx, xy, yx, yy);
    }

    function _FQ2Inv(uint256 x, uint256 y) internal view returns (uint256, uint256) {
        uint256 inv = _modInv(addmod(mulmod(y, y, FIELD_MODULUS), mulmod(x, x, FIELD_MODULUS), FIELD_MODULUS), FIELD_MODULUS);
        return (
            mulmod(x, inv, FIELD_MODULUS),
            FIELD_MODULUS - mulmod(y, inv, FIELD_MODULUS)
        );
    }

    function _isOnCurve(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (bool) {
        uint256 yyx;
        uint256 yyy;
        uint256 xxxx;
        uint256 xxxy;
        (yyx, yyy) = _FQ2Mul(yx, yy, yx, yy);
        (xxxx, xxxy) = _FQ2Mul(xx, xy, xx, xy);
        (xxxx, xxxy) = _FQ2Mul(xxxx, xxxy, xx, xy);
        (yyx, yyy) = _FQ2Sub(yyx, yyy, xxxx, xxxy);
        (yyx, yyy) = _FQ2Sub(yyx, yyy, TWISTBX, TWISTBY);
        return yyx == 0 && yyy == 0;
    }

    function _modInv(uint256 a, uint256 n) internal view returns (uint256 result) {
        bool success;
        assembly {
            let freemem := mload(0x40)
            mstore(freemem, 0x20)
            mstore(add(freemem,0x20), 0x20)
            mstore(add(freemem,0x40), 0x20)
            mstore(add(freemem,0x60), a)
            mstore(add(freemem,0x80), sub(n, 2))
            mstore(add(freemem,0xA0), n)
            success := staticcall(sub(gas(), 2000), 5, freemem, 0xC0, freemem, 0x20)
        //success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            result := mload(freemem)
        }
        require(success);
    }

    function _fromJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal view returns (
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy
    ) {
        uint256 invzx;
        uint256 invzy;
        (invzx, invzy) = _FQ2Inv(pt1zx, pt1zy);
        (pt2xx, pt2xy) = _FQ2Mul(pt1xx, pt1xy, invzx, invzy);
        (pt2yx, pt2yy) = _FQ2Mul(pt1yx, pt1yy, invzx, invzy);
    }

    function _ECTwistAddJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy,
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy,
        uint256 pt2zx, uint256 pt2zy) internal pure returns (uint256[6] memory pt3) {
        if (pt1zx == 0 && pt1zy == 0) {
            (
                pt3[PTXX], pt3[PTXY],
                pt3[PTYX], pt3[PTYY],
                pt3[PTZX], pt3[PTZY]
            ) = (
                pt2xx, pt2xy,
                pt2yx, pt2yy,
                pt2zx, pt2zy
            );
            return pt3;
        } else if (pt2zx == 0 && pt2zy == 0) {
            (
                pt3[PTXX], pt3[PTXY],
                pt3[PTYX], pt3[PTYY],
                pt3[PTZX], pt3[PTZY]
            ) = (
                pt1xx, pt1xy,
                pt1yx, pt1yy,
                pt1zx, pt1zy
            );
            return pt3;
        }

        (pt2yx,     pt2yy)     = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // U1 = y2 * z1
        (pt3[PTYX], pt3[PTYY]) = _FQ2Mul(pt1yx, pt1yy, pt2zx, pt2zy); // U2 = y1 * z2
        (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // V1 = x2 * z1
        (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1xx, pt1xy, pt2zx, pt2zy); // V2 = x1 * z2

        if (pt2xx == pt3[PTZX] && pt2xy == pt3[PTZY]) {
            if (pt2yx == pt3[PTYX] && pt2yy == pt3[PTYY]) {
                (
                    pt3[PTXX], pt3[PTXY],
                    pt3[PTYX], pt3[PTYY],
                    pt3[PTZX], pt3[PTZY]
                ) = _ECTwistDoubleJacobian(pt1xx, pt1xy, pt1yx, pt1yy, pt1zx, pt1zy);
                return pt3;
            }
            (
                pt3[PTXX], pt3[PTXY],
                pt3[PTYX], pt3[PTYY],
                pt3[PTZX], pt3[PTZY]
            ) = (
                1, 0,
                1, 0,
                0, 0
            );
            return pt3;
        }

        (pt2zx,     pt2zy)     = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // W = z1 * z2
        (pt1xx,     pt1xy)     = _FQ2Sub(pt2yx, pt2yy, pt3[PTYX], pt3[PTYY]); // U = U1 - U2
        (pt1yx,     pt1yy)     = _FQ2Sub(pt2xx, pt2xy, pt3[PTZX], pt3[PTZY]); // V = V1 - V2
        (pt1zx,     pt1zy)     = _FQ2Mul(pt1yx, pt1yy, pt1yx,     pt1yy);     // V_squared = V * V
        (pt2yx,     pt2yy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTZX], pt3[PTZY]); // V_squared_times_V2 = V_squared * V2
        (pt1zx,     pt1zy)     = _FQ2Mul(pt1zx, pt1zy, pt1yx,     pt1yy);     // V_cubed = V * V_squared
        (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // newz = V_cubed * W
        (pt2xx,     pt2xy)     = _FQ2Mul(pt1xx, pt1xy, pt1xx,     pt1xy);     // U * U
        (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt2zx,     pt2zy);     // U * U * W
        (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt1zx,     pt1zy);     // U * U * W - V_cubed
        (pt2zx,     pt2zy)     = _FQ2Muc(pt2yx, pt2yy, 2);                    // 2 * V_squared_times_V2
        (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt2zx,     pt2zy);     // A = U * U * W - V_cubed - 2 * V_squared_times_V2
        (pt3[PTXX], pt3[PTXY]) = _FQ2Mul(pt1yx, pt1yy, pt2xx,     pt2xy);     // newx = V * A
        (pt1yx,     pt1yy)     = _FQ2Sub(pt2yx, pt2yy, pt2xx,     pt2xy);     // V_squared_times_V2 - A
        (pt1yx,     pt1yy)     = _FQ2Mul(pt1xx, pt1xy, pt1yx,     pt1yy);     // U * (V_squared_times_V2 - A)
        (pt1xx,     pt1xy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTYX], pt3[PTYY]); // V_cubed * U2
        (pt3[PTYX], pt3[PTYY]) = _FQ2Sub(pt1yx, pt1yy, pt1xx,     pt1xy);     // newy = U * (V_squared_times_V2 - A) - V_cubed * U2
    }

    function _ECTwistDoubleJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal pure returns (
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy,
        uint256 pt2zx, uint256 pt2zy
    ) {
        (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 3);            // 3 * x
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1xx, pt1xy); // W = 3 * x * x
        (pt1zx, pt1zy) = _FQ2Mul(pt1yx, pt1yy, pt1zx, pt1zy); // S = y * z
        (pt2yx, pt2yy) = _FQ2Mul(pt1xx, pt1xy, pt1yx, pt1yy); // x * y
        (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // B = x * y * S
        (pt1xx, pt1xy) = _FQ2Mul(pt2xx, pt2xy, pt2xx, pt2xy); // W * W
        (pt2zx, pt2zy) = _FQ2Muc(pt2yx, pt2yy, 8);            // 8 * B
        (pt1xx, pt1xy) = _FQ2Sub(pt1xx, pt1xy, pt2zx, pt2zy); // H = W * W - 8 * B
        (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt1zx, pt1zy); // S_squared = S * S
        (pt2yx, pt2yy) = _FQ2Muc(pt2yx, pt2yy, 4);            // 4 * B
        (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt1xx, pt1xy); // 4 * B - H
        (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt2xx, pt2xy); // W * (4 * B - H)
        (pt2xx, pt2xy) = _FQ2Muc(pt1yx, pt1yy, 8);            // 8 * y
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1yx, pt1yy); // 8 * y * y
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt2zx, pt2zy); // 8 * y * y * S_squared
        (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt2xx, pt2xy); // newy = W * (4 * B - H) - 8 * y * y * S_squared
        (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 2);            // 2 * H
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // newx = 2 * H * S
        (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt2zx, pt2zy); // S * S_squared
        (pt2zx, pt2zy) = _FQ2Muc(pt2zx, pt2zy, 8);            // newz = 8 * S * S_squared
    }

    function _ECTwistMulJacobian(
        uint256 d,
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal pure returns (uint256[6] memory pt2) {
        while (d != 0) {
            if ((d & 1) != 0) {
                pt2 = _ECTwistAddJacobian(
                    pt2[PTXX], pt2[PTXY],
                    pt2[PTYX], pt2[PTYY],
                    pt2[PTZX], pt2[PTZY],
                    pt1xx, pt1xy,
                    pt1yx, pt1yy,
                    pt1zx, pt1zy);
            }
            (
                pt1xx, pt1xy,
                pt1yx, pt1yy,
                pt1zx, pt1zy
            ) = _ECTwistDoubleJacobian(
                pt1xx, pt1xy,
                pt1yx, pt1yy,
                pt1zx, pt1zy
            );

            d = d / 2;
        }
    }

    function equals(
        G1Point memory a, G1Point memory b
    ) view internal returns (bool) {
        return a.X==b.X && a.Y==b.Y;
    }

    function equals2(
        G2Point memory a, G2Point memory b
    ) view internal returns (bool) {
        return a.X[0]==b.X[0] && a.X[1]==b.X[1] && a.Y[0]==b.Y[0] && a.Y[1]==b.Y[1];
    }

    function HashToG1(string memory str) public payable returns (G1Point memory){

        return g1mul(P1(), uint256(keccak256(abi.encodePacked(str))));
    }

}
